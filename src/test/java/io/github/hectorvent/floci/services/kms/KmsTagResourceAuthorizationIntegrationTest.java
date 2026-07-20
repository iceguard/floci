package io.github.hectorvent.floci.services.kms;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(KmsTagResourceAuthorizationIntegrationTest.IamEnforcementProfile.class)
class KmsTagResourceAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String DEFAULT_REGION = "us-east-1";
    private static final String KMS_CONTENT_TYPE = "application/x-amz-json-1.1";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void allowsApprovedTagKeysWithExactKeyRegionRequestTagsAndExistingResourceTags() {
        KeyIdentity key = createKey(DEFAULT_REGION, Map.of("classification", "standard"));
        SessionCredentials credentials = callerWithPolicy("""
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "kms:TagResource",
                    "Resource": "%s",
                    "Condition": {
                      "StringEquals": {
                        "aws:RequestedRegion": "%s",
                        "aws:RequestTag/environment": "approved",
                        "aws:ResourceTag/classification": "standard"
                      },
                      "ForAllValues:StringEquals": {
                        "aws:TagKeys": ["environment", "owner"]
                      }
                    }
                  }]
                }
                """.formatted(key.arn(), DEFAULT_REGION));

        tagResource(credentials, DEFAULT_REGION, key.keyId(),
                Map.of("environment", "approved", "owner", "platform"))
                .statusCode(200);

        listResourceTags(DEFAULT_REGION, key.keyId())
                .statusCode(200)
                .body("Tags.find { it.TagKey == 'environment' }.TagValue", equalTo("approved"));
    }

    @Test
    void rejectsAForbiddenTagKey() {
        KeyIdentity key = createKey(DEFAULT_REGION, Map.of());
        SessionCredentials credentials = callerWithPolicy(allowWithDeny("""
                {
                  "Effect": "Deny",
                  "Action": "kms:TagResource",
                  "Resource": "*",
                  "Condition": {
                    "ForAnyValue:StringEquals": {
                      "aws:TagKeys": "restricted"
                    }
                  }
                }
                """));

        tagResource(credentials, DEFAULT_REGION, key.keyId(),
                Map.of("environment", "approved", "restricted", "blocked"))
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        assertTagAbsent(DEFAULT_REGION, key.keyId(), "environment");
        assertTagAbsent(DEFAULT_REGION, key.keyId(), "restricted");
    }

    @Test
    void rejectsAnExplicitlyDeniedKeyArn() {
        KeyIdentity key = createKey(DEFAULT_REGION, Map.of());
        SessionCredentials credentials = callerWithPolicy(allowWithDeny("""
                {
                  "Effect": "Deny",
                  "Action": "kms:TagResource",
                  "Resource": "%s"
                }
                """.formatted(key.arn())));

        tagResource(credentials, DEFAULT_REGION, key.keyId(), Map.of("attempt", "denied-key"))
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        assertTagAbsent(DEFAULT_REGION, key.keyId(), "attempt");
    }

    @Test
    void rejectsADisallowedRequestedRegion() {
        String disallowedRegion = "us-west-2";
        KeyIdentity key = createKey(disallowedRegion, Map.of());
        SessionCredentials credentials = callerWithPolicy(allowWithDeny("""
                {
                  "Effect": "Deny",
                  "Action": "kms:TagResource",
                  "Resource": "*",
                  "Condition": {
                    "StringNotEquals": {
                      "aws:RequestedRegion": "%s"
                    }
                  }
                }
                """.formatted(DEFAULT_REGION)));

        tagResource(credentials, disallowedRegion, key.keyId(), Map.of("attempt", "denied-region"))
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        assertTagAbsent(disallowedRegion, key.keyId(), "attempt");
    }

    @Test
    void rejectsADisallowedRequestedTag() {
        KeyIdentity key = createKey(DEFAULT_REGION, Map.of());
        SessionCredentials credentials = callerWithPolicy(allowWithDeny("""
                {
                  "Effect": "Deny",
                  "Action": "kms:TagResource",
                  "Resource": "*",
                  "Condition": {
                    "StringNotEquals": {
                      "aws:RequestTag/environment": "approved"
                    }
                  }
                }
                """));

        tagResource(credentials, DEFAULT_REGION, key.keyId(), Map.of("environment", "blocked"))
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        assertTagAbsent(DEFAULT_REGION, key.keyId(), "environment");
    }

    @Test
    void rejectsAProtectedExistingResourceTag() {
        KeyIdentity key = createKey(DEFAULT_REGION, Map.of("classification", "protected"));
        SessionCredentials credentials = callerWithPolicy(allowWithDeny("""
                {
                  "Effect": "Deny",
                  "Action": "kms:TagResource",
                  "Resource": "*",
                  "Condition": {
                    "StringEquals": {
                      "aws:ResourceTag/classification": "protected"
                    }
                  }
                }
                """));

        tagResource(credentials, DEFAULT_REGION, key.keyId(), Map.of("attempt", "protected-resource"))
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        assertTagAbsent(DEFAULT_REGION, key.keyId(), "attempt");
    }

    private static String allowWithDeny(String denyStatement) {
        return """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Effect": "Allow",
                      "Action": "kms:TagResource",
                      "Resource": "*"
                    },
                    %s
                  ]
                }
                """.formatted(denyStatement);
    }

    private static KeyIdentity createKey(String region, Map<String, String> tags) {
        var response = given()
                .header("Authorization", auth(ACCOUNT_ID, region, "kms"))
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType(KMS_CONTENT_TYPE)
                .body(Map.of(
                        "Description", "KMS authorization integration test",
                        "Tags", tagList(tags)))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract()
                .jsonPath();
        return new KeyIdentity(
                response.getString("KeyMetadata.KeyId"),
                response.getString("KeyMetadata.Arn"));
    }

    private static SessionCredentials callerWithPolicy(String policyDocument) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String roleName = "KmsTagger" + suffix;
        createRole(roleName);
        putRolePolicy(roleName, "KmsTagAuthorization", policyDocument);
        return assumeRole(roleName);
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", """
                        {
                          "Version": "2012-10-17",
                          "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole"
                          }]
                        }
                        """)
                .header("Authorization", auth(ACCOUNT_ID, DEFAULT_REGION, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static void putRolePolicy(String roleName, String policyName, String policyDocument) {
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", policyName)
                .formParam("PolicyDocument", policyDocument)
                .header("Authorization", auth(ACCOUNT_ID, DEFAULT_REGION, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        var response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "kms-tag-resource-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, DEFAULT_REGION, "sts"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract()
                .response();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static io.restassured.response.ValidatableResponse tagResource(
            SessionCredentials credentials, String region, String keyId, Map<String, String> tags) {
        return given()
                .header("Authorization", auth(credentials.accessKeyId(), region, "kms"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
                .header("X-Amz-Target", "TrentService.TagResource")
                .contentType(KMS_CONTENT_TYPE)
                .body(Map.of("KeyId", keyId, "Tags", tagList(tags)))
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse listResourceTags(String region, String keyId) {
        return given()
                .header("Authorization", auth(ACCOUNT_ID, region, "kms"))
                .header("X-Amz-Target", "TrentService.ListResourceTags")
                .contentType(KMS_CONTENT_TYPE)
                .body(Map.of("KeyId", keyId))
        .when()
                .post("/")
        .then();
    }

    private static void assertTagAbsent(String region, String keyId, String tagKey) {
        listResourceTags(region, keyId)
                .statusCode(200)
                .body("Tags.find { it.TagKey == '%s' }".formatted(tagKey), nullValue());
    }

    private static List<Map<String, String>> tagList(Map<String, String> tags) {
        return tags.entrySet().stream()
                .map(entry -> Map.of("TagKey", entry.getKey(), "TagValue", entry.getValue()))
                .toList();
    }

    private static String auth(String accessKeyId, String region, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260718/" + region + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private record KeyIdentity(String keyId, String arn) {}

    private record SessionCredentials(String accessKeyId, String sessionToken) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
