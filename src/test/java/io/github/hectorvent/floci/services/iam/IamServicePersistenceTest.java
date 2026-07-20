package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.PersistentStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IamServicePersistenceTest {

    @Test
    void roleInlinePolicyQuotaUsesPersistedAggregateAfterRestart(@TempDir Path directory) {
        Path rolesFile = directory.resolve("iam-roles.json");
        IamService first = newService(rolesFile);
        first.createRole("R", "/", "{}", null, 0, null);
        String firstPolicy = policyWithNonWhitespaceLength(6_000);
        String secondPolicy = policyWithNonWhitespaceLength(4_000);
        first.putRolePolicy("R", "first", firstPolicy);
        first.putRolePolicy("R", "second", secondPolicy);

        IamService restarted = newService(rolesFile);
        assertEquals(firstPolicy, restarted.getRolePolicy("R", "first"));
        assertEquals(secondPolicy, restarted.getRolePolicy("R", "second"));

        AwsException aggregateError = assertThrows(AwsException.class,
                () -> restarted.putRolePolicy("R", "third", policyWithNonWhitespaceLength(241)));
        assertEquals("LimitExceeded", aggregateError.getErrorCode());
        assertEquals(409, aggregateError.getHttpStatus());

        AwsException replacementError = assertThrows(AwsException.class,
                () -> restarted.putRolePolicy("R", "first", policyWithNonWhitespaceLength(6_241)));
        assertEquals("LimitExceeded", replacementError.getErrorCode());
        assertEquals(409, replacementError.getHttpStatus());
        assertEquals(firstPolicy, restarted.getRolePolicy("R", "first"));
        assertEquals(secondPolicy, restarted.getRolePolicy("R", "second"));
    }

    private static IamService newService(Path rolesFile) {
        PersistentStorage<String, IamRole> roles = new PersistentStorage<>(
                rolesFile, new TypeReference<Map<String, IamRole>>() {});
        roles.load();
        return new IamService(
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                roles,
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new RegionResolver("us-east-1", "000000000000"),
                false);
    }

    private static String policyWithNonWhitespaceLength(int targetLength) {
        String prefix = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"";
        String suffix = "\",\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}";
        return prefix + "x".repeat(targetLength - prefix.length() - suffix.length()) + suffix;
    }
}
