package io.github.hectorvent.floci.services.rds.proxy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.AccessKey;
import io.github.hectorvent.floci.testutil.IamServiceTestHelper;
import io.github.hectorvent.floci.testutil.SigV4TokenTestHelper;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RdsSigV4ValidatorTest {

    private static final String DB_USER_ARN =
            "arn:aws:rds-db:us-east-1:123456789012:dbuser:db-ABCDEFGHIJKLMNOPQRSTUVWX/app_user";

    @Test
    void validateAcceptsTokenSignedByStandardSigV4() throws Exception {
        String accessKeyId = "AKIAORACLETEST";
        String secretAccessKey = "oracle-secret-key-value";
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey(accessKeyId, secretAccessKey);

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);

        String token = SigV4TokenTestHelper.createRdsToken(
                "db.oracle-test.local",
                5432,
                "testuser",
                accessKeyId,
                secretAccessKey,
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "testuser"),
                "Validator must accept a well-formed SigV4 RDS authentication token");
    }

    @Test
    void validateAcceptsTokenSignedWithHostAndPort() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "admin"));
    }

    @Test
    void validateRejectsTokenWhenSignedForHostWithoutPort() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String validToken = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );
        String brokenToken = validToken.replace("db.example.local:5432/?", "db.example.local/?");

        assertFalse(validator.validate(brokenToken, "admin"));
    }

    @Test
    void validateRejectsExpiredToken() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(1200),
                900
        );

        assertFalse(validator.validate(token, "admin"));
    }

    @Test
    void validateRejectsTokenLifetimeLongerThanFifteenMinutes() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");
        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "admin", "AKIDRDS", "secret-rds",
                Instant.now(), 901);

        assertFalse(validator.validate(token, "admin"));
    }

    @Test
    void validateRejectsTokenTooFarInTheFuture() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");
        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "admin", "AKIDRDS", "secret-rds",
                Instant.now().plusSeconds(301), 900);

        assertFalse(validator.validate(token, "admin"));
    }

    @Test
    void validateRejectsTamperedSignature() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String validToken = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );
        String tamperedToken = validToken.replace("DBUser=admin", "DBUser=attacker");

        assertFalse(validator.validate(tamperedToken, "admin"));
    }

    @Test
    void validateRejectsTokenWithUnknownAccessKey() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDUNKNOWN",
                "AKIDUNKNOWN",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "admin"));
    }

    @Test
    void validateRejectsTokenMissingDbUser() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String validToken = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );
        String withoutDbUser = validToken.replaceFirst("DBUser=admin&", "");

        assertFalse(validator.validate(withoutDbUser, "admin"));
    }

    @Test
    void validateRejectsTokenForWrongUser() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "attacker"),
                "Token signed for 'admin' must be rejected when client connects as 'attacker'");
    }

    @Test
    void validateAcceptsTokenWhenClientUsernameIsNull() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, null),
                "Null clientUsername should skip the identity check (backwards compat)");
    }

    @Test
    void validateAcceptsTokenWithUrlEncodedDbUser() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        // Username with characters that require URL encoding exercises the
        // encoding path independently of the validator's decode logic
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "db+admin@example.com",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "db+admin@example.com"));
    }

    @Test
    void validateRejectsTokenWithWrongRegion() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );
        // Tampering with the region in the credential scope invalidates the signature
        String tamperedToken = token.replace("us-east-1", "eu-west-1");

        assertFalse(validator.validate(tamperedToken, "admin"));
    }

    @Test
    void validateRejectsTokenMissingSignatureParameter() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String validToken = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                "AKIDRDS",
                "secret-rds",
                Instant.now().minusSeconds(60),
                900
        );
        String withoutSignature = validToken.replaceFirst("&X-Amz-Signature=[0-9a-f]+", "");

        assertFalse(validator.validate(withoutSignature, "admin"));
    }

    @Test
    void validateAcceptsTokenSignedWithStsSessionCredentials() throws Exception {
        String accessKeyId = "ASIAIOSFODNN7EXAMPLE";
        String secretAccessKey = "sts-generated-secret-key";
        String sessionToken = "sts+session/token=";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, secretAccessKey, sessionToken);

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                accessKeyId,
                secretAccessKey,
                sessionToken,
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "admin"),
                "Validator must accept RDS IAM tokens signed with STS session credentials (ASIA… keys)");
    }

    @Test
    void validateRejectsStsTokenWithWrongSecret() throws Exception {
        String accessKeyId = "ASIAIOSFODNN7EXAMPLE";
        String sessionToken = "sts-session-token";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, "correct-secret", sessionToken);

        RdsSigV4Validator validator = new RdsSigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local",
                5432,
                "admin",
                accessKeyId,
                "wrong-secret",
                sessionToken,
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "admin"),
                "Validator must reject STS token signed with wrong secret");
    }

    @Test
    void validateRejectsSessionTokenForLongTermCredential() throws Exception {
        String accessKeyId = "AKIDRDS";
        String secretAccessKey = "secret-rds";
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey(
                accessKeyId, secretAccessKey);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "admin", accessKeyId, secretAccessKey,
                "unexpected-session-token", Instant.now().minusSeconds(60), 900);

        assertFalse(new RdsSigV4Validator(iamService).validate(token, "admin"));
    }

    @Test
    void validateRejectsStsTokenWithoutSessionToken() throws Exception {
        String accessKeyId = "ASIAMISSINGTOKEN";
        String secretAccessKey = "temporary-secret";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, secretAccessKey, "required-token");

        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "admin", accessKeyId, secretAccessKey,
                Instant.now().minusSeconds(60), 900);

        assertFalse(new RdsSigV4Validator(iamService).validate(token, "admin"));
    }

    @Test
    void validateRejectsStsTokenWithWrongSessionToken() throws Exception {
        String accessKeyId = "ASIAWRONGTOKEN";
        String secretAccessKey = "temporary-secret";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, secretAccessKey, "required-token");

        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "admin", accessKeyId, secretAccessKey,
                "wrong-token", Instant.now().minusSeconds(60), 900);

        assertFalse(new RdsSigV4Validator(iamService).validate(token, "admin"));
    }

    @Test
    void validateRejectsExpiredStsCredential() throws Exception {
        String accessKeyId = "ASIAEXPIREDTOKEN";
        String secretAccessKey = "temporary-secret";
        String sessionToken = "expired-token";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, secretAccessKey, sessionToken, Instant.now().minusSeconds(1));

        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "admin", accessKeyId, secretAccessKey,
                sessionToken, Instant.now().minusSeconds(60), 900);

        assertFalse(new RdsSigV4Validator(iamService).validate(token, "admin"));
    }

    @Test
    void validateRejectsUnknownStsCredentialWithoutCompatibilityFallback() throws Exception {
        String accessKeyId = "ASIAUNKNOWNRAWKEY";
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDRDS", "secret-rds");

        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "admin", accessKeyId, accessKeyId,
                "unknown-token", Instant.now().minusSeconds(60), 900);

        assertFalse(new RdsSigV4Validator(iamService).validate(token, "admin"));
    }

    @Test
    void authorizeAcceptsTokenSignedWithDefaultCredential() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        RdsSigV4Validator validator = authorizedValidator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "app_user", "test", "test",
                Instant.now().minusSeconds(60), 900);

        assertTrue(authorize(validator, token));
    }

    @Test
    void authorizeAcceptsTokenWithExactRdsDbConnectPermission() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        iamService.createUser("application", "/");
        AccessKey key = iamService.createAccessKey("application");
        iamService.putUserPolicy("application", "rds-connect", policyFor(DB_USER_ARN));
        RdsSigV4Validator validator = authorizedValidator(iamService);
        String token = tokenFor("app_user", key);

        assertTrue(authorize(validator, token));
    }

    @Test
    void authorizeAcceptsInstanceProfileSessionWithExactRdsDbConnectPermission() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        var role = iamService.createRole("application-role", "/", "{}", null, 3600, null);
        iamService.putRolePolicy("application-role", "rds-connect", policyFor(DB_USER_ARN));
        String accessKeyId = "ASIAAPPLICATIONROLE";
        String secretAccessKey = "instance-profile-secret";
        String sessionToken = "instance-profile-session-token";
        iamService.registerSession(accessKeyId, secretAccessKey, sessionToken, role.getArn(),
                "application-session", "123456789012", role.getRoleId(),
                Instant.now().plusSeconds(3600), null, "123456789012", null, null);
        RdsSigV4Validator validator = authorizedValidator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "app_user", accessKeyId, secretAccessKey,
                sessionToken, "us-east-1", Instant.now().minusSeconds(60), 900);

        assertTrue(authorize(validator, token));
    }

    @Test
    void authorizeRejectsTokenScopedToDifferentDatabaseUser() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        iamService.createUser("application", "/");
        AccessKey key = iamService.createAccessKey("application");
        iamService.putUserPolicy("application", "rds-connect", policyFor(
                "arn:aws:rds-db:us-east-1:123456789012:dbuser:db-ABCDEFGHIJKLMNOPQRSTUVWX/other_user"));
        RdsSigV4Validator validator = authorizedValidator(iamService);
        String token = tokenFor("app_user", key);

        assertFalse(authorize(validator, token));
    }

    @Test
    void authorizeRejectsKnownCallerWithoutRdsDbConnectPermission() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        iamService.createUser("application", "/");
        AccessKey key = iamService.createAccessKey("application");
        RdsSigV4Validator validator = authorizedValidator(iamService);

        assertFalse(authorize(validator, tokenFor("app_user", key)));
    }

    @Test
    void authorizeRejectsSelfConsistentTokenForDifferentEndpoint() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        iamService.createUser("application", "/");
        AccessKey key = iamService.createAccessKey("application");
        iamService.putUserPolicy("application", "rds-connect", policyFor(DB_USER_ARN));
        RdsSigV4Validator validator = authorizedValidator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "other.example.local", 5432, "app_user", key.getAccessKeyId(), key.getSecretAccessKey(),
                Instant.now().minusSeconds(60), 900);

        assertFalse(authorize(validator, token));
    }

    @Test
    void authorizeRejectsSelfConsistentTokenForDifferentRegion() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        iamService.createUser("application", "/");
        AccessKey key = iamService.createAccessKey("application");
        iamService.putUserPolicy("application", "rds-connect", policyFor(DB_USER_ARN));
        RdsSigV4Validator validator = authorizedValidator(iamService);
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "app_user", key.getAccessKeyId(), key.getSecretAccessKey(),
                null, "eu-west-1", Instant.now().minusSeconds(60), 900);

        assertFalse(authorize(validator, token));
    }

    @Test
    void authorizeRejectsInactiveAccessKey() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        iamService.createUser("application", "/");
        AccessKey key = iamService.createAccessKey("application");
        iamService.putUserPolicy("application", "rds-connect", policyFor(DB_USER_ARN));
        String token = tokenFor("app_user", key);
        iamService.updateAccessKey("application", key.getAccessKeyId(), "Inactive");

        assertFalse(authorize(authorizedValidator(iamService), token));
    }

    @Test
    void validateRejectsUnknownAccessKeyEvenWhenTokenUsesKeyIdAsSecret() throws Exception {
        IamService iamService = IamServiceTestHelper.emptyIamService();
        RdsSigV4Validator validator = authorizedValidator(iamService);
        String accessKeyId = "AKIAUNKNOWNSELFSECRET";
        String token = SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, "app_user", accessKeyId, accessKeyId,
                Instant.now().minusSeconds(60), 900);

        assertFalse(validator.validate(token, "app_user"));
    }

    private static RdsSigV4Validator authorizedValidator(IamService iamService) {
        return new RdsSigV4Validator(iamService, new IamPolicyEvaluator(new ObjectMapper()));
    }

    private static String tokenFor(String user, AccessKey key) throws Exception {
        return SigV4TokenTestHelper.createRdsToken(
                "db.example.local", 5432, user, key.getAccessKeyId(), key.getSecretAccessKey(),
                Instant.now().minusSeconds(60), 900);
    }

    private static boolean authorize(RdsSigV4Validator validator, String token) {
        return validator.validateAndAuthorize(
                token, "app_user", DB_USER_ARN, "db.example.local", 5432);
    }

    private static String policyFor(String resource) {
        return """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "rds-db:connect",
                    "Resource": "%s"
                  }]
                }
                """.formatted(resource);
    }
}
