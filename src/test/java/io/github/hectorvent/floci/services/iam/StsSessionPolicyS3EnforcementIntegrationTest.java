package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(StsSessionPolicyS3EnforcementIntegrationTest.IamEnforcementProfile.class)
class StsSessionPolicyS3EnforcementIntegrationTest {

    private static final String CALLER_ACCOUNT_ID = "111122223333";
    private static final String ROLE_ACCOUNT_ID = "222233334444";
    private static final String TARGET_ACCOUNT_ID = "333344445555";
    private static final String DEFAULT_ACCOUNT_ID = "000000000000";
    private static final String REGION = "us-east-1";

    @Test
    void assumeRoleSessionPolicyDenyRestrictsS3PutObject() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "session-policy-" + suffix;
        String roleName = "SessionPolicyRole" + suffix;

        createBucket(bucket);
        createRole(roleName);
        putBroadS3RolePolicy(roleName, bucket);

        SessionCredentials credentials = assumeRoleWithS3SessionPolicy(roleName, bucket);

        given()
                .header("Authorization", auth(credentials.accessKeyId(), "s3"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
                .contentType("text/plain")
                .body("allowed")
        .when()
                .put("/" + bucket + "/allowed/file.txt")
        .then()
                .statusCode(200);

        given()
                .header("Authorization", auth(credentials.accessKeyId(), "s3"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
                .contentType("text/plain")
                .body("denied")
        .when()
                .put("/" + bucket + "/blocked/file.txt")
        .then()
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    @Test
    void assumeRoleSessionPolicyListBucketPrefixConditionRestrictsListObjects() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "session-policy-prefix-" + suffix;
        String roleName = "SessionPolicyPrefixRole" + suffix;
        String allowedPrefix = "my_namespace/table_" + suffix + "/";

        createBucket(bucket);
        createRole(roleName);
        putBroadS3RolePolicy(roleName, bucket);
        putObject(bucket, allowedPrefix + "metadata.json");
        putObject(bucket, "other_namespace/table_" + suffix + "/metadata.json");

        SessionCredentials credentials = assumeRoleWithS3ListPrefixSessionPolicy(roleName, bucket, allowedPrefix);

        given()
                .header("Authorization", auth(credentials.accessKeyId(), "s3"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
                .queryParam("list-type", "2")
                .queryParam("prefix", allowedPrefix)
        .when()
                .get("/" + bucket)
        .then()
                .statusCode(200)
                .body(containsString("<Key>" + allowedPrefix + "metadata.json</Key>"));

        given()
                .header("Authorization", auth(credentials.accessKeyId(), "s3"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
                .queryParam("list-type", "2")
                .queryParam("prefix", "other_namespace/table_" + suffix + "/")
        .when()
                .get("/" + bucket)
        .then()
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));
    }

    @Test
    void getSessionTokenRetainsIssuingUserPolicyForRuntimeEnforcement() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String userName = "session-user-" + suffix;
        String bucket = "session-user-policy-" + suffix;
        createBucket(bucket);

        given()
                .formParam("Action", "CreateUser")
                .formParam("UserName", userName)
                .header("Authorization", auth(DEFAULT_ACCOUNT_ID, "iam"))
            .when().post("/").then().statusCode(200);
        given()
                .formParam("Action", "PutUserPolicy")
                .formParam("UserName", userName)
                .formParam("PolicyName", "ListBucketsOnly")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Deny","Action":["sts:GetSessionToken","sts:GetCallerIdentity"],
                       "Resource":"*"},
                      {"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}
                    ]}
                    """)
                .header("Authorization", auth(DEFAULT_ACCOUNT_ID, "iam"))
            .when().post("/").then().statusCode(200);
        io.restassured.path.xml.XmlPath accessKey = given()
                .formParam("Action", "CreateAccessKey")
                .formParam("UserName", userName)
                .header("Authorization", auth(DEFAULT_ACCOUNT_ID, "iam"))
            .when().post("/").then().statusCode(200).extract().xmlPath();
        String sourceAccessKeyId = accessKey.getString(
                "CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");

        io.restassured.path.xml.XmlPath token = given()
                .formParam("Action", "GetSessionToken")
                .header("Authorization", auth(sourceAccessKeyId, "sts"))
            .when().post("/").then().statusCode(200).extract().xmlPath();
        String prefix = "GetSessionTokenResponse.GetSessionTokenResult.Credentials.";
        SessionCredentials credentials = new SessionCredentials(
                token.getString(prefix + "AccessKeyId"), token.getString(prefix + "SessionToken"));

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(credentials.accessKeyId(), "sts"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
            .when().post("/")
            .then().statusCode(200);

        given()
                .header("Authorization", auth(credentials.accessKeyId(), "s3"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
            .when().get("/")
            .then().statusCode(200);

        given()
                .header("Authorization", auth(credentials.accessKeyId(), "s3"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
                .contentType("text/plain").body("denied")
            .when().put("/" + bucket + "/denied.txt")
            .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));
    }

    @Test
    void getSessionTokenCredentialsApplyMfaAndStsIntrinsicRestrictions() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String userName = "session-restrictions-" + suffix;

        given()
                .formParam("Action", "CreateUser")
                .formParam("UserName", userName)
                .header("Authorization", auth(DEFAULT_ACCOUNT_ID, "iam"))
            .when().post("/").then().statusCode(200);
        given()
                .formParam("Action", "PutUserPolicy")
                .formParam("UserName", userName)
                .formParam("PolicyName", "BroadIamAndSts")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":["iam:ListUsers","sts:*"],"Resource":"*"}
                    ]}
                    """)
                .header("Authorization", auth(DEFAULT_ACCOUNT_ID, "iam"))
            .when().post("/").then().statusCode(200);
        io.restassured.path.xml.XmlPath accessKey = given()
                .formParam("Action", "CreateAccessKey")
                .formParam("UserName", userName)
                .header("Authorization", auth(DEFAULT_ACCOUNT_ID, "iam"))
            .when().post("/").then().statusCode(200).extract().xmlPath();
        String sourceAccessKeyId = accessKey.getString(
                "CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");

        io.restassured.path.xml.XmlPath withoutMfaResponse = given()
                .formParam("Action", "GetSessionToken")
                .header("Authorization", auth(sourceAccessKeyId, "sts"))
            .when().post("/").then().statusCode(200).extract().xmlPath();
        SessionCredentials withoutMfa = getSessionTokenCredentials(withoutMfaResponse);

        given()
                .formParam("Action", "ListUsers")
                .header("Authorization", auth(withoutMfa.accessKeyId(), "iam"))
                .header("X-Amz-Security-Token", withoutMfa.sessionToken())
            .when().post("/")
            .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));
        given()
                .formParam("Action", "DecodeAuthorizationMessage")
                .formParam("EncodedMessage", "message")
                .header("Authorization", auth(withoutMfa.accessKeyId(), "sts"))
                .header("X-Amz-Security-Token", withoutMfa.sessionToken())
            .when().post("/")
            .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));
        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(withoutMfa.accessKeyId(), "sts"))
                .header("X-Amz-Security-Token", withoutMfa.sessionToken())
            .when().post("/")
            .then().statusCode(200);

        given()
                .formParam("Action", "GetSessionToken")
                .formParam("SerialNumber", "arn:aws:iam::" + DEFAULT_ACCOUNT_ID + ":mfa/" + userName)
                .formParam("TokenCode", "123456")
                .header("Authorization", auth(sourceAccessKeyId, "sts"))
            .when().post("/")
            .then().statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(containsString("MultiFactorAuthentication failed"));
    }

    @Test
    void assumedRoleSessionUsesAuthenticatedCallerAccountForChainedTrust() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String sourceRoleName = "SourceRole" + suffix;
        String targetRoleName = "TargetRole" + suffix;
        String targetRoleArn = "arn:aws:iam::" + TARGET_ACCOUNT_ID + ":role/" + targetRoleName;

        createRole(sourceRoleName);
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", sourceRoleName)
                .formParam("PolicyName", "AssumeTarget")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}
                    ]}
                    """)
                .header("Authorization", auth(ROLE_ACCOUNT_ID, "iam"))
            .when().post("/").then().statusCode(200);

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", targetRoleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},
                       "Action":"sts:AssumeRole"}
                    ]}
                    """.formatted(ROLE_ACCOUNT_ID))
                .header("Authorization", auth(TARGET_ACCOUNT_ID, "iam"))
            .when().post("/").then().statusCode(200);

        io.restassured.path.xml.XmlPath first = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ROLE_ACCOUNT_ID + ":role/" + sourceRoleName)
                .formParam("RoleSessionName", "source-session")
                .header("Authorization", auth(CALLER_ACCOUNT_ID, "sts"))
            .when().post("/").then().statusCode(200).extract().xmlPath();
        SessionCredentials source = sessionCredentials(first);

        io.restassured.path.xml.XmlPath second = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", targetRoleArn)
                .formParam("RoleSessionName", "target-session")
                .header("Authorization", auth(source.accessKeyId(), "sts"))
                .header("X-Amz-Security-Token", source.sessionToken())
            .when().post("/").then().statusCode(200).extract().xmlPath();
        org.junit.jupiter.api.Assertions.assertEquals(
                "arn:aws:sts::" + TARGET_ACCOUNT_ID + ":assumed-role/" + targetRoleName + "/target-session",
                second.getString("AssumeRoleResponse.AssumeRoleResult.AssumedRoleUser.Arn"));
    }

    private static void createBucket(String bucket) {
        given()
                .header("Authorization", auth(ROLE_ACCOUNT_ID, "s3"))
        .when()
                .put("/" + bucket)
        .then()
                .statusCode(200);
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", """
                    {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Effect": "Allow",
                          "Principal": { "AWS": "*" },
                          "Action": "sts:AssumeRole"
                        }
                      ]
                    }
                    """)
                .header("Authorization", auth(ROLE_ACCOUNT_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static void putBroadS3RolePolicy(String roleName, String bucket) {
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "AllowS3")
                .formParam("PolicyDocument", """
                    {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Effect": "Allow",
                          "Action": "s3:*",
                          "Resource": [
                            "arn:aws:s3:::%1$s",
                            "arn:aws:s3:::%1$s/*"
                          ]
                        }
                      ]
                    }
                    """.formatted(bucket))
                .header("Authorization", auth(ROLE_ACCOUNT_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static void putObject(String bucket, String key) {
        given()
                .header("Authorization", auth(ROLE_ACCOUNT_ID, "s3"))
                .contentType("application/json")
                .body("{}")
        .when()
                .put("/" + bucket + "/" + key)
        .then()
                .statusCode(200);
    }

    private static SessionCredentials assumeRoleWithS3SessionPolicy(String roleName, String bucket) {
        io.restassured.path.xml.XmlPath response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ROLE_ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "session-policy-test")
                .formParam("Policy", """
                    {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Effect": "Allow",
                          "Action": "s3:*",
                          "Resource": [
                            "arn:aws:s3:::%1$s",
                            "arn:aws:s3:::%1$s/*"
                          ]
                        },
                        {
                          "Effect": "Deny",
                          "Action": "s3:*",
                          "Resource": "arn:aws:s3:::%1$s/blocked/*"
                        }
                      ]
                    }
                    """.formatted(bucket))
                .header("Authorization", auth(CALLER_ACCOUNT_ID, "sts"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract().xmlPath();
        return sessionCredentials(response);
    }

    private static SessionCredentials assumeRoleWithS3ListPrefixSessionPolicy(
            String roleName, String bucket, String allowedPrefix) {
        io.restassured.path.xml.XmlPath response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ROLE_ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "session-policy-prefix-test")
                .formParam("Policy", """
                    {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Effect": "Allow",
                          "Action": "s3:ListBucket",
                          "Resource": "arn:aws:s3:::%1$s",
                          "Condition": {
                            "StringLike": {
                              "s3:prefix": [
                                "%2$s",
                                "%2$s*"
                              ]
                            }
                          }
                        },
                        {
                          "Effect": "Allow",
                          "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            "s3:DeleteObject"
                          ],
                          "Resource": "arn:aws:s3:::%1$s/%2$s*"
                        }
                      ]
                    }
                    """.formatted(bucket, allowedPrefix))
                .header("Authorization", auth(CALLER_ACCOUNT_ID, "sts"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract().xmlPath();
        return sessionCredentials(response);
    }

    private static SessionCredentials sessionCredentials(io.restassured.path.xml.XmlPath response) {
        String prefix = "AssumeRoleResponse.AssumeRoleResult.Credentials.";
        return new SessionCredentials(response.getString(prefix + "AccessKeyId"),
                response.getString(prefix + "SessionToken"));
    }

    private static SessionCredentials getSessionTokenCredentials(
            io.restassured.path.xml.XmlPath response) {
        String prefix = "GetSessionTokenResponse.GetSessionTokenResult.Credentials.";
        return new SessionCredentials(response.getString(prefix + "AccessKeyId"),
                response.getString(prefix + "SessionToken"));
    }

    private record SessionCredentials(String accessKeyId, String sessionToken) {}

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260629/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
