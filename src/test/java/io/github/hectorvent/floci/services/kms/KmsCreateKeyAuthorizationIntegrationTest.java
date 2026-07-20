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
@TestProfile(KmsCreateKeyAuthorizationIntegrationTest.IamEnforcementProfile.class)
class KmsCreateKeyAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String ALLOWED_REGION = "us-west-2";
    private static final String KMS_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final Map<String, String> REQUIRED_TAGS = Map.of(
            "example.io:definition-id", "sample",
            "example.io:managed-by", "floci");

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void authorizesCreateKeyFromRequestedRegionAndRequestTags() {
        SessionCredentials credentials = callerWithCreateKeyPolicy();

        createKey(credentials, ALLOWED_REGION, REQUIRED_TAGS)
                .statusCode(200)
                .body("KeyMetadata.Arn", startsWith(
                        "arn:aws:kms:" + ALLOWED_REGION + ":" + ACCOUNT_ID + ":key/"));

        createKey(credentials, "us-east-1", REQUIRED_TAGS)
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
        createKey(credentials, ALLOWED_REGION, Map.of(
                "example.io:definition-id", "sample",
                "example.io:managed-by", "other"))
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
        createKey(credentials, ALLOWED_REGION, Map.of(
                "example.io:definition-id", "sample"))
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
        createKey(credentials, ALLOWED_REGION, Map.of(
                "example.io:definition-id", "sample",
                "example.io:managed-by", "floci",
                "restricted", "blocked"))
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        SessionCredentials keyResourceOnlyCaller = callerWithPolicy("""
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "kms:CreateKey",
                    "Resource": "arn:aws:kms:%s:%s:key/*"
                  }]
                }
                """.formatted(ALLOWED_REGION, ACCOUNT_ID));
        createKey(keyResourceOnlyCaller, ALLOWED_REGION, REQUIRED_TAGS)
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static SessionCredentials callerWithCreateKeyPolicy() {
        return callerWithPolicy("""
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "kms:CreateKey",
                    "Resource": "*",
                    "Condition": {
                      "StringEquals": {
                        "aws:RequestedRegion": "%s",
                        "aws:RequestTag/example.io:definition-id": "sample",
                        "aws:RequestTag/example.io:managed-by": "floci"
                      },
                      "ForAllValues:StringEquals": {
                        "aws:TagKeys": [
                          "example.io:definition-id",
                          "example.io:managed-by"
                        ]
                      }
                    }
                  }]
                }
                """.formatted(ALLOWED_REGION));
    }

    private static SessionCredentials callerWithPolicy(String policyDocument) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String roleName = "KmsKeyCreator" + suffix;
        createRole(roleName);
        putRolePolicy(roleName, "KmsCreateKeyAuthorization", policyDocument);
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
                .header("Authorization", auth(ACCOUNT_ID, ALLOWED_REGION, "iam"))
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
                .header("Authorization", auth(ACCOUNT_ID, ALLOWED_REGION, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        var response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "kms-create-key-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, ALLOWED_REGION, "sts"))
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

    private static io.restassured.response.ValidatableResponse createKey(
            SessionCredentials credentials, String region, Map<String, String> tags) {
        List<Map<String, String>> tagList = tags.entrySet().stream()
                .map(entry -> Map.of("TagKey", entry.getKey(), "TagValue", entry.getValue()))
                .toList();
        return given()
                .header("Authorization", auth(credentials.accessKeyId(), region, "kms"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType(KMS_CONTENT_TYPE)
                .body(Map.of(
                        "Description", "KMS CreateKey authorization integration test",
                        "Tags", tagList))
        .when()
                .post("/")
        .then();
    }

    private static String auth(String accessKeyId, String region, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + region + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private record SessionCredentials(String accessKeyId, String sessionToken) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
