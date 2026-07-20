package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.github.hectorvent.floci.services.iam.model.SessionCredential;
import io.github.hectorvent.floci.services.iam.model.SessionCredential.SessionType;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
class StsSessionCredentialsSdkIntegrationTest {

    private static final String ACCOUNT = "222233334444";
    private static final String REGION = "us-east-1";

    @Inject
    IamService iamService;

    @Test
    void issuedSessionCredentialReturnsExactIdentityAndRejectsInvalidTokens() {
        String roleName = "ProvisioningRole" + java.util.UUID.randomUUID().toString().substring(0, 8);
        createRole(ACCOUNT, roleName);
        io.restassured.path.xml.XmlPath assumeRole = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/" + roleName)
                .formParam("RoleSessionName", "requested-session")
                .header("Authorization", auth("111122223333"))
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract()
                .xmlPath();

        String accessKeyId = assumeRole.getString(
                "AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
        String token = assumeRole.getString(
                "AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken");
        String assumedRoleId = assumeRole.getString(
                "AssumeRoleResponse.AssumeRoleResult.AssumedRoleUser.AssumedRoleId");

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(accessKeyId))
                .header("X-Amz-Security-Token", token)
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Account", equalTo(ACCOUNT))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn",
                        equalTo("arn:aws:sts::" + ACCOUNT
                                + ":assumed-role/" + roleName + "/requested-session"))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.UserId", equalTo(assumedRoleId));

        assertInvalid(accessKeyId, null);
        assertInvalid(accessKeyId, "wrong-token");
        assertInvalid("ASIAUNKNOWNSESSION", "unknown-token");
    }

    @Test
    void expiredIssuedSessionReturnsExpiredTokenInsteadOfRootIdentity() {
        iamService.registerSession(
                "ASIAEXPIREDQUERY",
                "expired-secret",
                "expired-token",
                "arn:aws:iam::" + ACCOUNT + ":role/ExpiredRole",
                "expired-session",
                ACCOUNT,
                "AROAEXPIREDQUERY",
                Instant.now().minusSeconds(1),
                null,
                "111122223333");

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth("ASIAEXPIREDQUERY"))
                .header("X-Amz-Security-Token", "expired-token")
            .when()
                .post("/")
            .then()
                .statusCode(403)
                .body(containsString("<Code>ExpiredToken</Code>"));
    }

    @Test
    void getSessionTokenRetainsIssuingUserIdentityAndPolicies() {
        String userName = "session-user-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        iamService.createUser(userName, "/");
        iamService.putUserPolicy(userName, "ListBucketsOnly", """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}
                ]}
                """);
        io.github.hectorvent.floci.services.iam.model.AccessKey sourceKey = iamService.createAccessKey(userName);
        io.github.hectorvent.floci.services.iam.model.IamUser user = iamService.getUser(userName);

        io.restassured.path.xml.XmlPath tokenResponse = given()
                .formParam("Action", "GetSessionToken")
                .header("Authorization", auth(sourceKey.getAccessKeyId()))
            .when().post("/")
            .then().statusCode(200).extract().xmlPath();
        String prefix = "GetSessionTokenResponse.GetSessionTokenResult.Credentials.";
        String accessKeyId = tokenResponse.getString(prefix + "AccessKeyId");
        String sessionToken = tokenResponse.getString(prefix + "SessionToken");

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(accessKeyId))
                .header("X-Amz-Security-Token", sessionToken)
            .when().post("/")
            .then().statusCode(200)
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn", equalTo(user.getArn()))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.UserId", equalTo(user.getUserId()));

        org.junit.jupiter.api.Assertions.assertEquals(
                iamService.resolveCallerPolicies(sourceKey.getAccessKeyId()),
                iamService.resolveCallerPolicies(accessKeyId));
        org.junit.jupiter.api.Assertions.assertThrows(io.github.hectorvent.floci.core.common.AwsException.class,
                () -> iamService.resolveCallerContext(accessKeyId, "wrong-token"));

        SessionCredential stored = iamService.requireActiveSession(accessKeyId, sessionToken);
        org.junit.jupiter.api.Assertions.assertEquals(SessionType.GET_SESSION_TOKEN, stored.getSessionType());
        org.junit.jupiter.api.Assertions.assertFalse(stored.isMfaAuthenticated());
        org.junit.jupiter.api.Assertions.assertTrue(stored.isPrincipalBindingRequired());

        given()
                .formParam("Action", "GetSessionToken")
                .header("Authorization", auth(accessKeyId))
                .header("X-Amz-Security-Token", sessionToken)
            .when().post("/")
            .then().statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(containsString("Cannot call GetSessionToken with session credentials"));

        iamService.deleteUser(userName);
        io.github.hectorvent.floci.services.iam.model.IamUser replacement =
                iamService.createUser(userName, "/");
        org.junit.jupiter.api.Assertions.assertNotEquals(user.getUserId(), replacement.getUserId());

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(accessKeyId))
                .header("X-Amz-Security-Token", sessionToken)
            .when().post("/")
            .then().statusCode(403)
                .body(containsString("<Code>InvalidClientTokenId</Code>"));
    }

    @Test
    void getSessionTokenUsesIndependentSecureCredentialsAndRejectsUnverifiedMfa() {
        io.restassured.path.xml.XmlPath first = given()
                .formParam("Action", "GetSessionToken")
                .header("Authorization", auth("111122223333"))
            .when().post("/")
            .then().statusCode(200).extract().xmlPath();
        io.restassured.path.xml.XmlPath second = given()
                .formParam("Action", "GetSessionToken")
                .header("Authorization", auth("111122223333"))
            .when().post("/")
            .then().statusCode(200).extract().xmlPath();

        String prefix = "GetSessionTokenResponse.GetSessionTokenResult.Credentials.";
        String firstAccessKey = first.getString(prefix + "AccessKeyId");
        String secondAccessKey = second.getString(prefix + "AccessKeyId");
        String secondToken = second.getString(prefix + "SessionToken");

        org.junit.jupiter.api.Assertions.assertNotEquals(firstAccessKey, secondAccessKey);
        org.junit.jupiter.api.Assertions.assertNotEquals(
                first.getString(prefix + "SecretAccessKey"),
                second.getString(prefix + "SecretAccessKey"));
        org.junit.jupiter.api.Assertions.assertNotEquals(
                first.getString(prefix + "SessionToken"), secondToken);
        SessionCredential stored = iamService.requireActiveSession(secondAccessKey, secondToken);
        org.junit.jupiter.api.Assertions.assertEquals(SessionType.GET_SESSION_TOKEN, stored.getSessionType());
        org.junit.jupiter.api.Assertions.assertFalse(stored.isMfaAuthenticated());
        org.junit.jupiter.api.Assertions.assertFalse(stored.isPrincipalBindingRequired());

        given()
                .formParam("Action", "GetSessionToken")
                .formParam("SerialNumber", "arn:aws:iam::111122223333:mfa/test-user")
                .formParam("TokenCode", "123456")
                .header("Authorization", auth("111122223333"))
            .when().post("/")
            .then().statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(containsString("MultiFactorAuthentication failed"));

        given()
                .formParam("Action", "GetSessionToken")
                .formParam("SerialNumber", "arn:aws:iam::111122223333:mfa/test-user")
                .header("Authorization", auth("111122223333"))
            .when().post("/")
            .then().statusCode(400)
                .body(containsString("<Code>ValidationError</Code>"));
    }

    @Test
    void getSessionTokenRestrictionsApplyWhenPolicyEnforcementIsDisabled() {
        io.restassured.path.xml.XmlPath response = given()
                .formParam("Action", "GetSessionToken")
                .header("Authorization", auth("111122223333"))
            .when().post("/")
            .then().statusCode(200).extract().xmlPath();
        String prefix = "GetSessionTokenResponse.GetSessionTokenResult.Credentials.";
        String accessKeyId = response.getString(prefix + "AccessKeyId");
        String sessionToken = response.getString(prefix + "SessionToken");

        given()
                .formParam("Action", "ListUsers")
                .header("Authorization", auth(accessKeyId, "iam"))
                .header("X-Amz-Security-Token", sessionToken)
            .when().post("/")
            .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));

        given()
                .formParam("Action", "DecodeAuthorizationMessage")
                .formParam("EncodedMessage", "message")
                .header("Authorization", auth(accessKeyId))
                .header("X-Amz-Security-Token", sessionToken)
            .when().post("/")
            .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(accessKeyId))
                .header("X-Amz-Security-Token", sessionToken)
            .when().post("/")
            .then().statusCode(200);
    }

    @Test
    void unknownRoleCannotIssueCredentialsThatAcquireLaterPermissions() {
        String roleName = "missing-role-" + java.util.UUID.randomUUID().toString().substring(0, 8);

        given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/" + roleName)
                .formParam("RoleSessionName", "must-not-exist")
                .header("Authorization", auth("111122223333"))
            .when().post("/")
            .then().statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"));

        createRole(ACCOUNT, roleName);
        given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/" + roleName)
                .formParam("RoleSessionName", "bound-session")
                .header("Authorization", auth("111122223333"))
            .when().post("/")
            .then().statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"));
    }

    @Test
    void webIdentityAndSamlCannotIssueSessionsForUnknownRoles() {
        String suffix = java.util.UUID.randomUUID().toString().substring(0, 8);

        given()
                .formParam("Action", "AssumeRoleWithWebIdentity")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/missing-web-" + suffix)
                .formParam("RoleSessionName", "web-session")
                .formParam("WebIdentityToken", "header.payload.signature")
            .when().post("/")
            .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));

        given()
                .formParam("Action", "AssumeRoleWithSAML")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/missing-saml-" + suffix)
                .formParam("PrincipalArn", "arn:aws:iam::" + ACCOUNT + ":saml-provider/Test")
                .formParam("SAMLAssertion", "assertion")
            .when().post("/")
            .then().statusCode(403).body(containsString("<Code>AccessDenied</Code>"));
    }

    @Test
    void assumedRoleSessionDoesNotSurviveRoleRecreation() {
        String roleName = "bound-role-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        io.github.hectorvent.floci.services.iam.model.IamRole original =
                iamService.createRole(roleName, "/", "{}", null, 0, null);
        io.restassured.path.xml.XmlPath assumed = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", original.getArn())
                .formParam("RoleSessionName", "bound-session")
                .header("Authorization", auth("111122223333"))
            .when().post("/")
            .then().statusCode(200).extract().xmlPath();
        String prefix = "AssumeRoleResponse.AssumeRoleResult.Credentials.";
        String accessKeyId = assumed.getString(prefix + "AccessKeyId");
        String sessionToken = assumed.getString(prefix + "SessionToken");

        iamService.deleteRole(roleName);
        io.github.hectorvent.floci.services.iam.model.IamRole replacement =
                iamService.createRole(roleName, "/", "{}", null, 0, null);
        org.junit.jupiter.api.Assertions.assertNotEquals(original.getRoleId(), replacement.getRoleId());

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(accessKeyId))
                .header("X-Amz-Security-Token", sessionToken)
            .when().post("/")
            .then().statusCode(403)
                .body(containsString("<Code>InvalidClientTokenId</Code>"));
    }

    @Test
    void webIdentityAndSamlSessionsRetainTheirReturnedIdentity() {
        createRole(ACCOUNT, "WebIdentityRole");
        createRole(ACCOUNT, "SamlRole");
        io.restassured.path.xml.XmlPath webIdentity = given()
                .formParam("Action", "AssumeRoleWithWebIdentity")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/WebIdentityRole")
                .formParam("RoleSessionName", "web-session")
                .formParam("WebIdentityToken", "header.payload.signature")
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .extract()
                .xmlPath();
        assertReturnedIdentity(webIdentity, "AssumeRoleWithWebIdentity", "WebIdentityRole", "web-session");

        io.restassured.path.xml.XmlPath saml = given()
                .formParam("Action", "AssumeRoleWithSAML")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/SamlRole")
                .formParam("PrincipalArn", "arn:aws:iam::" + ACCOUNT + ":saml-provider/Test")
                .formParam("SAMLAssertion", "assertion")
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .extract()
                .xmlPath();
        assertReturnedIdentity(saml, "AssumeRoleWithSAML", "SamlRole", "saml-session");
    }

    private static void assertReturnedIdentity(io.restassured.path.xml.XmlPath response,
                                               String action, String roleName, String sessionName) {
        String prefix = action + "Response." + action + "Result.";
        String accessKeyId = response.getString(prefix + "Credentials.AccessKeyId");
        String token = response.getString(prefix + "Credentials.SessionToken");
        String assumedRoleId = response.getString(prefix + "AssumedRoleUser.AssumedRoleId");

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(accessKeyId))
                .header("X-Amz-Security-Token", token)
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Account", equalTo(ACCOUNT))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn",
                        equalTo("arn:aws:sts::" + ACCOUNT + ":assumed-role/"
                                + roleName + "/" + sessionName))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.UserId", equalTo(assumedRoleId));
    }

    private static void assertInvalid(String accessKeyId, String token) {
        io.restassured.specification.RequestSpecification request = given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", auth(accessKeyId));
        if (token != null) {
            request.header("X-Amz-Security-Token", token);
        }
        request.when()
                .post("/")
            .then()
                .statusCode(403)
                .body(containsString("<Code>InvalidClientTokenId</Code>"));
    }

    private static void createRole(String accountId, String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", "{}")
                .header("Authorization", auth(accountId, "iam"))
            .when().post("/")
            .then().statusCode(200);
    }

    private static String auth(String accessKeyId) {
        return auth(accessKeyId, "sts");
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + REGION
                + "/" + service + "/aws4_request, SignedHeaders=host, Signature=abc";
    }
}
