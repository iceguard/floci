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
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(KmsExistingKeyAuthorizationIntegrationTest.IamEnforcementProfile.class)
class KmsExistingKeyAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-west-2";
    private static final String KMS_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final Map<String, String> REQUIRED_TAGS = Map.of(
            "example.io:definition-id", "sample",
            "example.io:managed-by", "floci");

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void authorizesExistingKeyByExactArnAndPersistedResourceTags() {
        KeyIdentity allowedKey = createKey(REQUIRED_TAGS);
        KeyIdentity differentKey = createKey(REQUIRED_TAGS);
        KeyIdentity mismatchedTagKey = createKey(Map.of(
                "example.io:definition-id", "other",
                "example.io:managed-by", "floci"));

        SessionCredentials exactKeyCaller = callerWithPolicy(rotationPolicy(allowedKey.arn()));
        enableKeyRotation(exactKeyCaller, allowedKey.keyId()).statusCode(200);

        enableKeyRotation(exactKeyCaller, differentKey.keyId())
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        SessionCredentials taggedKeyCaller = callerWithPolicy(rotationPolicy(
                "arn:aws:kms:" + REGION + ":" + ACCOUNT_ID + ":key/*"));
        enableKeyRotation(taggedKeyCaller, mismatchedTagKey.keyId())
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        SessionCredentials noRotationCaller = callerWithPolicy("""
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "kms:DescribeKey",
                    "Resource": "*"
                  }]
                }
                """);
        enableKeyRotation(noRotationCaller, allowedKey.keyId())
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static String rotationPolicy(String resource) {
        return """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "kms:EnableKeyRotation",
                    "Resource": "%s",
                    "Condition": {
                      "StringEquals": {
                        "aws:ResourceTag/example.io:definition-id": "sample",
                        "aws:ResourceTag/example.io:managed-by": "floci"
                      }
                    }
                  }]
                }
                """.formatted(resource);
    }

    private static KeyIdentity createKey(Map<String, String> tags) {
        var response = given()
                .header("Authorization", auth(ACCOUNT_ID, REGION, "kms"))
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType(KMS_CONTENT_TYPE)
                .body(Map.of(
                        "Description", "KMS existing-key authorization integration test",
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
        String roleName = "KmsKeyOperator" + suffix;
        createRole(roleName);
        putRolePolicy(roleName, "KmsExistingKeyAuthorization", policyDocument);
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
                .header("Authorization", auth(ACCOUNT_ID, REGION, "iam"))
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
                .header("Authorization", auth(ACCOUNT_ID, REGION, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        var response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "kms-existing-key-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, REGION, "sts"))
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

    private static io.restassured.response.ValidatableResponse enableKeyRotation(
            SessionCredentials credentials, String keyId) {
        return given()
                .header("Authorization", auth(credentials.accessKeyId(), REGION, "kms"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
                .header("X-Amz-Target", "TrentService.EnableKeyRotation")
                .contentType(KMS_CONTENT_TYPE)
                .body(Map.of("KeyId", keyId))
        .when()
                .post("/")
        .then();
    }

    private static List<Map<String, String>> tagList(Map<String, String> tags) {
        return tags.entrySet().stream()
                .map(entry -> Map.of("TagKey", entry.getKey(), "TagValue", entry.getValue()))
                .toList();
    }

    private static String auth(String accessKeyId, String region, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + region + "/" + service
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
