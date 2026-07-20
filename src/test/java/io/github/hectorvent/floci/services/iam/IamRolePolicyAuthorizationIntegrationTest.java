package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(IamRolePolicyAuthorizationIntegrationTest.IamEnforcementProfile.class)
class IamRolePolicyAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";
    private static final String ALLOWED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess";
    private static final String DENIED_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess";
    private static final String TRUST_POLICY = """
            {
              "Version": "2012-10-17",
              "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole"
              }]
            }
            """;

    @Test
    void authorizesExactCreateAttachAndDetachRoleResources() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "RolePolicyOperator" + suffix;
        String allowedRole = "AllowedWorkload" + suffix;
        String deniedRole = "DeniedWorkload" + suffix;
        String deniedCreateRole = "DeniedCreate" + suffix;
        String allowedRoleArn = roleArn("/provisioned/", allowedRole);

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, deniedRole, "/protected/").statusCode(200);
        putRolePolicy(callerRole, "ScopedRolePolicyOperations", """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Effect": "Allow",
                      "Action": "iam:CreateRole",
                      "Resource": "%s"
                    },
                    {
                      "Effect": "Allow",
                      "Action": ["iam:AttachRolePolicy", "iam:DetachRolePolicy"],
                      "Resource": "%s",
                      "Condition": {
                        "ArnEquals": {"iam:PolicyARN": "%s"}
                      }
                    }
                  ]
                }
                """.formatted(allowedRoleArn, allowedRoleArn, ALLOWED_POLICY_ARN));
        SessionCredentials credentials = assumeRole(callerRole);

        createRole(credentials, allowedRole, "/provisioned/")
                .statusCode(200)
                .body(containsString(allowedRoleArn));
        rolePolicyRequest(ACCOUNT_ID, "AttachRolePolicy", deniedRole, ALLOWED_POLICY_ARN)
                .statusCode(200);
        createRole(credentials, deniedCreateRole, "/protected/")
                .statusCode(403)
                .body(containsString("iam:CreateRole"));

        rolePolicyRequest(credentials, "AttachRolePolicy", allowedRole, ALLOWED_POLICY_ARN)
                .statusCode(200);
        rolePolicyRequest(credentials, "AttachRolePolicy", deniedRole, ALLOWED_POLICY_ARN)
                .statusCode(403)
                .body(containsString("iam:AttachRolePolicy"));
        rolePolicyRequest(credentials, "AttachRolePolicy", allowedRole, DENIED_POLICY_ARN)
                .statusCode(403)
                .body(containsString("iam:AttachRolePolicy"));
        listAttachedRolePolicies(allowedRole)
                .statusCode(200)
                .body(containsString(ALLOWED_POLICY_ARN))
                .body(not(containsString(DENIED_POLICY_ARN)));

        rolePolicyRequest(ACCOUNT_ID, "AttachRolePolicy", allowedRole, DENIED_POLICY_ARN)
                .statusCode(200);
        rolePolicyRequest(credentials, "DetachRolePolicy", allowedRole, DENIED_POLICY_ARN)
                .statusCode(403)
                .body(containsString("iam:DetachRolePolicy"));
        rolePolicyRequest(credentials, "DetachRolePolicy", deniedRole, ALLOWED_POLICY_ARN)
                .statusCode(403)
                .body(containsString("iam:DetachRolePolicy"));
        listAttachedRolePolicies(deniedRole)
                .statusCode(200)
                .body(containsString(ALLOWED_POLICY_ARN));
        rolePolicyRequest(credentials, "DetachRolePolicy", allowedRole, ALLOWED_POLICY_ARN)
                .statusCode(200);
        listAttachedRolePolicies(allowedRole)
                .statusCode(200)
                .body(not(containsString(ALLOWED_POLICY_ARN)))
                .body(containsString(DENIED_POLICY_ARN));
    }

    private static io.restassured.response.ValidatableResponse createRole(
            String accessKeyId, String roleName, String path) {
        return queryRequest(accessKeyId, "iam", Map.of(
                "Action", "CreateRole",
                "RoleName", roleName,
                "Path", path,
                "AssumeRolePolicyDocument", TRUST_POLICY));
    }

    private static io.restassured.response.ValidatableResponse createRole(
            SessionCredentials credentials, String roleName, String path) {
        return queryRequest(credentials, "iam", Map.of(
                "Action", "CreateRole",
                "RoleName", roleName,
                "Path", path,
                "AssumeRolePolicyDocument", TRUST_POLICY));
    }

    private static void putRolePolicy(String roleName, String policyName, String policyDocument) {
        queryRequest(ACCOUNT_ID, "iam", Map.of(
                "Action", "PutRolePolicy",
                "RoleName", roleName,
                "PolicyName", policyName,
                "PolicyDocument", policyDocument)).statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        var response = queryRequest(ACCOUNT_ID, "sts", Map.of(
                "Action", "AssumeRole",
                "RoleArn", roleArn("/", roleName),
                "RoleSessionName", "role-policy-authorization"))
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static io.restassured.response.ValidatableResponse rolePolicyRequest(
            String accessKeyId, String action, String roleName, String policyArn) {
        return queryRequest(accessKeyId, "iam", Map.of(
                "Action", action,
                "RoleName", roleName,
                "PolicyArn", policyArn));
    }

    private static io.restassured.response.ValidatableResponse rolePolicyRequest(
            SessionCredentials credentials, String action, String roleName, String policyArn) {
        return queryRequest(credentials, "iam", Map.of(
                "Action", action,
                "RoleName", roleName,
                "PolicyArn", policyArn));
    }

    private static io.restassured.response.ValidatableResponse listAttachedRolePolicies(String roleName) {
        return queryRequest(ACCOUNT_ID, "iam", Map.of(
                "Action", "ListAttachedRolePolicies",
                "RoleName", roleName));
    }

    private static io.restassured.response.ValidatableResponse queryRequest(
            String accessKeyId, String service, Map<String, String> parameters) {
        String body = parameters.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
        return given()
                .contentType("application/x-www-form-urlencoded; charset=UTF-8")
                .body(body)
                .header("Authorization", auth(accessKeyId, service))
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse queryRequest(
            SessionCredentials credentials, String service, Map<String, String> parameters) {
        String body = parameters.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
        return given()
                .contentType("application/x-www-form-urlencoded; charset=UTF-8")
                .body(body)
                .header("Authorization", auth(credentials.accessKeyId(), service))
                .header("X-Amz-Security-Token", credentials.sessionToken())
        .when()
                .post("/")
        .then();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String roleArn(String path, String roleName) {
        return "arn:aws:iam::" + ACCOUNT_ID + ":role" + path + roleName;
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + REGION + "/" + service
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
