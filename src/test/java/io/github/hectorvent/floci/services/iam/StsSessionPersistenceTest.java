package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.PersistentStorage;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.SessionCredential;
import io.github.hectorvent.floci.services.iam.model.SessionCredential.SessionType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.nio.file.Files;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StsSessionPersistenceTest {

    @TempDir
    Path tempDir;

    @Test
    void sessionCredentialIdentityAndTokenSurviveRestart() {
        Path file = tempDir.resolve("iam-sessions.json");
        PersistentStorage<String, SessionCredential> firstStore = storage(file);
        InMemoryStorage<String, IamRole> roles = new InMemoryStorage<>();
        IamService first = service(firstStore, roles);
        IamRole role = first.createRole("PersistedRole", "/", "{}", null, 0, null);
        Instant expiration = Instant.now().plusSeconds(3600).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);

        first.registerSession(
                "ASIAPERSISTEDSESSION",
                "persisted-secret",
                "persisted-token",
                role.getArn(),
                "persisted-session",
                "000000000000",
                role.getRoleId(),
                expiration,
                "{\"Version\":\"2012-10-17\"}",
                "111122223333",
                "arn:aws:iam::111122223333:user/session-source",
                "AIDAPERSISTEDSOURCE",
                SessionType.ASSUME_ROLE,
                false,
                true);

        PersistentStorage<String, SessionCredential> restartedStore = storage(file);
        restartedStore.load();
        IamService restarted = service(restartedStore, roles);
        SessionCredential persisted = restarted.requireActiveSession(
                "ASIAPERSISTEDSESSION", "persisted-token");

        assertEquals("persisted-secret", persisted.getSecretAccessKey());
        assertEquals("persisted-token", persisted.getSessionToken());
        assertEquals("persisted-session", persisted.getRoleSessionName());
        assertEquals("000000000000", persisted.getTargetAccountId());
        assertEquals(role.getRoleId(), persisted.getAssumedRolePrincipalId());
        assertEquals(expiration, persisted.getExpiration());
        assertEquals("111122223333", persisted.getOriginAccountId());
        assertEquals("arn:aws:iam::111122223333:user/session-source",
                persisted.getSourcePrincipalArn());
        assertEquals("AIDAPERSISTEDSOURCE", persisted.getSourcePrincipalId());
        assertEquals(SessionType.ASSUME_ROLE, persisted.getSessionType());
        assertFalse(persisted.isMfaAuthenticated());
        assertTrue(persisted.isPrincipalBindingRequired());
        assertEquals(role.getRoleId() + ":persisted-session",
                restarted.resolveSessionIdentity("ASIAPERSISTEDSESSION", "persisted-token").userId());
    }

    @Test
    void legacyJsonWithoutSessionTokenLoadsButCannotAuthenticate() throws Exception {
        Path file = tempDir.resolve("legacy-iam-sessions.json");
        Files.writeString(file, """
                {
                  "ASIALEGACYPERSISTED": {
                    "accessKeyId": "ASIALEGACYPERSISTED",
                    "secretAccessKey": "legacy-secret",
                    "roleArn": "arn:aws:iam::222233334444:role/LegacyRole",
                    "expiration": "2099-01-01T00:00:00Z",
                    "originAccountId": "111122223333"
                  }
                }
                """);
        PersistentStorage<String, SessionCredential> legacyStore = storage(file);
        legacyStore.load();
        IamService service = service(legacyStore);

        AwsException error = assertThrows(AwsException.class,
                () -> service.resolveSessionIdentity("ASIALEGACYPERSISTED", "legacy-token"));

        assertEquals("InvalidClientTokenId", error.getErrorCode());
    }

    @Test
    void persistedUnverifiedMfaFlagCannotElevateIamAccessAfterRestart() {
        Path file = tempDir.resolve("mfa-iam-sessions.json");
        PersistentStorage<String, SessionCredential> firstStore = storage(file);
        IamService first = service(firstStore);
        first.registerSession(
                "ASIAPERSISTEDMFA",
                "persisted-secret",
                "persisted-token",
                null,
                null,
                "000000000000",
                null,
                Instant.now().plusSeconds(3600),
                null,
                "000000000000",
                "arn:aws:iam::000000000000:root",
                "000000000000",
                SessionType.GET_SESSION_TOKEN,
                true,
                false);

        PersistentStorage<String, SessionCredential> restartedStore = storage(file);
        restartedStore.load();
        SessionCredential persisted = service(restartedStore)
                .requireActiveSession("ASIAPERSISTEDMFA", "persisted-token");

        assertEquals(SessionType.GET_SESSION_TOKEN, persisted.getSessionType());
        assertTrue(persisted.isMfaAuthenticated());
        assertFalse(service(restartedStore).isSessionActionAllowed(
                "ASIAPERSISTEDMFA", "persisted-token", "iam:ListUsers"));
    }

    private static PersistentStorage<String, SessionCredential> storage(Path file) {
        return new PersistentStorage<>(file, new TypeReference<Map<String, SessionCredential>>() {});
    }

    private static IamService service(PersistentStorage<String, SessionCredential> sessions) {
        return service(sessions, new InMemoryStorage<>());
    }

    private static IamService service(PersistentStorage<String, SessionCredential> sessions,
                                      InMemoryStorage<String, IamRole> roles) {
        return new IamService(
                new InMemoryStorage<>(), new InMemoryStorage<>(), roles,
                new InMemoryStorage<>(), new InMemoryStorage<>(), new InMemoryStorage<>(), sessions,
                new RegionResolver("us-east-1", "000000000000"));
    }
}
