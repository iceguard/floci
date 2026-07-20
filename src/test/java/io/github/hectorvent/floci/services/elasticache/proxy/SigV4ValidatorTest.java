package io.github.hectorvent.floci.services.elasticache.proxy;

import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.testutil.IamServiceTestHelper;
import io.github.hectorvent.floci.testutil.SigV4TokenTestHelper;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigV4ValidatorTest {

    @Test
    void validateAcceptsTokenForMatchingReplicationGroup() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "cache-cluster-01", "default"));
        assertTrue(validator.validate(token, "CACHE-CLUSTER-01", "default"));
    }

    @Test
    void validateRejectsTokenForDifferentReplicationGroup() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "other-cluster", "default"));
    }

    @Test
    void validateRejectsTamperedSignature() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String validToken = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );
        String tamperedToken = validToken.replace("User=default", "User=other");

        assertFalse(validator.validate(tamperedToken, "cache-cluster-01", "default"));
    }

    @Test
    void validateAcceptsTokenWhenExpectedGroupIsNull() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, null, "default"));
    }

    @Test
    void validateRejectsExpiredToken() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(1200),
                900
        );

        assertFalse(validator.validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsTokenWithUnknownAccessKey() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDUNKNOWN",
                "AKIDUNKNOWN",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsTokenForWrongUser() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "cache-cluster-01", "attacker"),
                "Token signed for 'default' must be rejected when client authenticates as 'attacker'");
    }

    @Test
    void validateRejectsTokenWhenExpectedUsernameIsNull() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(validator.validate(token, "cache-cluster-01", null),
                "Redis AUTH must supply the username bound into the IAM token");
    }

    @Test
    void validateRejectsCorrectlySignedTokenWithoutUser() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                null,
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertFalse(new SigV4Validator(iamService)
                .validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateAcceptsTokenWithUrlEncodedUser() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        // Username with characters that require URL encoding exercises the
        // encoding path independently of the validator's decode logic
        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "user+name@domain.com",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );

        assertTrue(validator.validate(token, "cache-cluster-01", "user+name@domain.com"));
    }

    @Test
    void validateRejectsTokenMissingActionParameter() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String validToken = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );
        String withoutAction = validToken.replaceFirst("Action=connect&", "");

        assertFalse(validator.validate(withoutAction, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsTokenMissingSignatureParameter() throws Exception {
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        SigV4Validator validator = new SigV4Validator(iamService);
        String validToken = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01",
                "default",
                "AKIDCACHE",
                "secret-cache",
                Instant.now().minusSeconds(60),
                900
        );
        String withoutSignature = validToken.replaceFirst("&X-Amz-Signature=[0-9a-f]+", "");

        assertFalse(validator.validate(withoutSignature, "cache-cluster-01", "default"));
    }

    @Test
    void validateAcceptsTokenSignedWithStsSessionCredentials() throws Exception {
        String accessKeyId = "ASIACACHESESSION";
        String secretAccessKey = "temporary-secret";
        String sessionToken = "cache-session-token";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, secretAccessKey, sessionToken);

        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01", "default", accessKeyId, secretAccessKey,
                sessionToken, Instant.now().minusSeconds(60), 900);

        assertTrue(new SigV4Validator(iamService)
                .validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsStsTokenWithoutSessionToken() throws Exception {
        String accessKeyId = "ASIACACHEMISSING";
        String secretAccessKey = "temporary-secret";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, secretAccessKey, "required-token");

        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01", "default", accessKeyId, secretAccessKey,
                Instant.now().minusSeconds(60), 900);

        assertFalse(new SigV4Validator(iamService)
                .validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsStsTokenWithWrongSessionToken() throws Exception {
        String accessKeyId = "ASIACACHEWRONG";
        String secretAccessKey = "temporary-secret";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, secretAccessKey, "required-token");

        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01", "default", accessKeyId, secretAccessKey,
                "wrong-token", Instant.now().minusSeconds(60), 900);

        assertFalse(new SigV4Validator(iamService)
                .validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsExpiredStsCredential() throws Exception {
        String accessKeyId = "ASIACACHEEXPIRED";
        String secretAccessKey = "temporary-secret";
        String sessionToken = "expired-token";
        IamService iamService = IamServiceTestHelper.iamServiceWithSessionCredential(
                accessKeyId, secretAccessKey, sessionToken, Instant.now().minusSeconds(1));

        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01", "default", accessKeyId, secretAccessKey,
                sessionToken, Instant.now().minusSeconds(60), 900);

        assertFalse(new SigV4Validator(iamService)
                .validate(token, "cache-cluster-01", "default"));
    }

    @Test
    void validateRejectsUnknownStsCredentialWithoutCompatibilityFallback() throws Exception {
        String accessKeyId = "ASIACACHEUNKNOWN";
        IamService iamService = IamServiceTestHelper.iamServiceWithAccessKey("AKIDCACHE", "secret-cache");

        String token = SigV4TokenTestHelper.createElastiCacheToken(
                "cache-cluster-01", "default", accessKeyId, accessKeyId,
                "unknown-token", Instant.now().minusSeconds(60), 900);

        assertFalse(new SigV4Validator(iamService)
                .validate(token, "cache-cluster-01", "default"));
    }
}
