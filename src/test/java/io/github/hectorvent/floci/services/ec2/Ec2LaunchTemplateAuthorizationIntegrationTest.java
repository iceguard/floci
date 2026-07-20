package io.github.hectorvent.floci.services.ec2;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(Ec2LaunchTemplateAuthorizationIntegrationTest.IamEnforcementProfile.class)
class Ec2LaunchTemplateAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";

    @Test
    void authorizesCreationAndTagOnCreateAgainstTheFutureLaunchTemplateArn() {
        SessionCredentials credentials = createSession(REGION, "floci", true, true);

        createLaunchTemplate(credentials, "floci")
                .statusCode(200)
                .body("CreateLaunchTemplateResponse.launchTemplate.launchTemplateId", startsWith("lt-"));
    }

    @Test
    void rejectsCreationForTheWrongRegionOrRequestTag() {
        SessionCredentials wrongRegionSession = createSession("eu-west-1", "floci", true, true);
        createLaunchTemplate(wrongRegionSession, "floci")
                .statusCode(403)
                .body("Response.Errors.Error.Code", equalTo("UnauthorizedOperation"))
                .body(containsString("ec2:CreateLaunchTemplate"));

        SessionCredentials wrongTagSession = createSession(REGION, "floci", true, true);
        createLaunchTemplate(wrongTagSession, "other")
                .statusCode(403)
                .body("Response.Errors.Error.Code", equalTo("UnauthorizedOperation"))
                .body(containsString("ec2:CreateLaunchTemplate"));
    }

    @Test
    void rejectsTaggedCreationWithoutCreateTagsPermission() {
        SessionCredentials credentials = createSession(REGION, "floci", false, true);

        createLaunchTemplate(credentials, "floci")
                .statusCode(403)
                .body("Response.Errors.Error.Code", equalTo("UnauthorizedOperation"))
                .body(containsString("ec2:CreateTags"));
    }

    @Test
    void authorizesDeletionByIdAndNameUsingPersistedResourceTags() {
        SessionCredentials credentials = createSession(REGION, "floci", true, true);
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String byIdName = "authorization-id-" + suffix;
        String byId = createLaunchTemplate(credentials, byIdName, "floci")
                .statusCode(200)
                .extract().path("CreateLaunchTemplateResponse.launchTemplate.launchTemplateId");
        String byName = "authorization-name-" + suffix;
        createLaunchTemplate(credentials, byName, "floci").statusCode(200);

        deleteLaunchTemplate(credentials, byId, null).statusCode(200);
        deleteLaunchTemplate(credentials, null, byName).statusCode(200);
    }

    @Test
    void rejectsDeletionForWrongResourceTagsOrMissingPermissionWithoutDeleting() {
        SessionCredentials credentials = createSession(REGION, "floci", true, true);
        String mismatchedId = createLaunchTemplate(ACCOUNT_ID, "other")
                .statusCode(200)
                .extract().path("CreateLaunchTemplateResponse.launchTemplate.launchTemplateId");
        deleteLaunchTemplate(credentials, mismatchedId, null)
                .statusCode(403)
                .body("Response.Errors.Error.Code", equalTo("UnauthorizedOperation"))
                .body(containsString("ec2:DeleteLaunchTemplate"));
        describeLaunchTemplate(mismatchedId).statusCode(200);

        SessionCredentials noDeleteSession = createSession(REGION, "floci", true, false);
        String protectedId = createLaunchTemplate(ACCOUNT_ID, "floci")
                .statusCode(200)
                .extract().path("CreateLaunchTemplateResponse.launchTemplate.launchTemplateId");
        deleteLaunchTemplate(noDeleteSession, protectedId, null)
                .statusCode(403)
                .body("Response.Errors.Error.Code", equalTo("UnauthorizedOperation"));
        describeLaunchTemplate(protectedId).statusCode(200);
    }

    private static SessionCredentials createSession(
            String policyRegion, String managedBy, boolean allowCreateTags, boolean allowDelete) {
        String roleName = "LaunchTemplateRole" + UUID.randomUUID().toString().substring(0, 8);
        createRole(roleName);
        String createTagsStatement = allowCreateTags ? """
                , {
                  "Effect": "Allow",
                  "Action": "ec2:CreateTags",
                  "Resource": "arn:aws:ec2:%s:%s:launch-template/*",
                  "Condition": {"StringEquals": {
                    "aws:RequestTag/example.io:definition-id": "example",
                    "aws:RequestTag/example.io:managed-by": "%s",
                    "ec2:CreateAction": "CreateLaunchTemplate"
                  }}
                }
                """.formatted(policyRegion, ACCOUNT_ID, managedBy) : "";
        String deleteStatement = allowDelete ? """
                , {
                  "Effect": "Allow",
                  "Action": "ec2:DeleteLaunchTemplate",
                  "Resource": "arn:aws:ec2:%s:%s:launch-template/*",
                  "Condition": {"StringEquals": {
                    "aws:RequestedRegion": "%s",
                    "aws:ResourceTag/example.io:definition-id": "example",
                    "aws:ResourceTag/example.io:managed-by": "%s"
                  }}
                }
                """.formatted(policyRegion, ACCOUNT_ID, policyRegion, managedBy) : "";
        putRolePolicy(roleName, """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "ec2:CreateLaunchTemplate",
                    "Resource": "arn:aws:ec2:%s:%s:launch-template/*",
                    "Condition": {"StringEquals": {
                      "aws:RequestedRegion": "%s",
                      "aws:RequestTag/example.io:definition-id": "example",
                      "aws:RequestTag/example.io:managed-by": "%s"
                    }}
                  }%s%s]
                }
                """.formatted(
                policyRegion, ACCOUNT_ID, policyRegion, managedBy,
                createTagsStatement, deleteStatement));
        return assumeRole(roleName);
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument", """
                        {"Version":"2012-10-17","Statement":[{
                          "Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"
                        }]}
                        """)
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    private static void putRolePolicy(String roleName, String policyDocument) {
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "ScopedLaunchTemplateLifecycle")
                .formParam("PolicyDocument", policyDocument)
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        io.restassured.response.Response response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "launch-template-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, "sts"))
        .when().post("/")
        .then().statusCode(200)
                .extract().response();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static io.restassured.response.ValidatableResponse createLaunchTemplate(
            SessionCredentials credentials, String managedBy) {
        return createLaunchTemplate(
                credentials, "authorization-" + UUID.randomUUID().toString().substring(0, 8), managedBy);
    }

    private static io.restassured.response.ValidatableResponse createLaunchTemplate(
            String accessKeyId, String managedBy) {
        return createLaunchTemplate(
                accessKeyId, "authorization-" + UUID.randomUUID().toString().substring(0, 8), managedBy);
    }

    private static io.restassured.response.ValidatableResponse createLaunchTemplate(
            String accessKeyId, String name, String managedBy) {
        return createLaunchTemplate(given()
                .header("Authorization", auth(accessKeyId, "ec2")), name, managedBy);
    }

    private static io.restassured.response.ValidatableResponse createLaunchTemplate(
            SessionCredentials credentials, String name, String managedBy) {
        return createLaunchTemplate(given()
                .header("Authorization", auth(credentials.accessKeyId(), "ec2"))
                .header("X-Amz-Security-Token", credentials.sessionToken()), name, managedBy);
    }

    private static io.restassured.response.ValidatableResponse createLaunchTemplate(
            io.restassured.specification.RequestSpecification request, String name, String managedBy) {
        return request
                .formParam("Action", "CreateLaunchTemplate")
                .formParam("LaunchTemplateName", name)
                .formParam("LaunchTemplateData.ImageId", "ami-0abcdef1234567890")
                .formParam("LaunchTemplateData.InstanceType", "t3.micro")
                .formParam("TagSpecification.1.ResourceType", "launch-template")
                .formParam("TagSpecification.1.Tag.1.Key", "example.io:definition-id")
                .formParam("TagSpecification.1.Tag.1.Value", "example")
                .formParam("TagSpecification.1.Tag.2.Key", "example.io:managed-by")
                .formParam("TagSpecification.1.Tag.2.Value", managedBy)
        .when().post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse deleteLaunchTemplate(
            SessionCredentials credentials, String id, String name) {
        io.restassured.specification.RequestSpecification request = given()
                .formParam("Action", "DeleteLaunchTemplate")
                .header("Authorization", auth(credentials.accessKeyId(), "ec2"))
                .header("X-Amz-Security-Token", credentials.sessionToken());
        if (id != null) {
            request.formParam("LaunchTemplateId", id);
        }
        if (name != null) {
            request.formParam("LaunchTemplateName", name);
        }
        return request.when().post("/").then();
    }

    private static io.restassured.response.ValidatableResponse describeLaunchTemplate(String id) {
        return given()
                .formParam("Action", "DescribeLaunchTemplates")
                .formParam("LaunchTemplateId.1", id)
                .header("Authorization", auth(ACCOUNT_ID, "ec2"))
        .when().post("/")
        .then();
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
