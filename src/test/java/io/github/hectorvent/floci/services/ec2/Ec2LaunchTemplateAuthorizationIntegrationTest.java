package io.github.hectorvent.floci.services.ec2;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.InstanceType;
import software.amazon.awssdk.services.ec2.model.ResourceType;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ec2.model.TagSpecification;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

    @Test
    void authorizesVersionCreationAgainstExistingTemplateArnAndResourceTagsWithSdk() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String byIdName = "version-by-id-" + suffix;
        String byNameName = "version-by-name-" + suffix;
        String wrongTagName = "version-wrong-tag-" + suffix;
        String missingPermissionName = "version-missing-permission-" + suffix;

        try (Ec2Client root = ec2Client(ACCOUNT_ID, "test-secret-key", null)) {
            String byId = createLaunchTemplate(root, byIdName, "floci");
            createLaunchTemplate(root, byNameName, "floci");
            String wrongTagId = createLaunchTemplate(root, wrongTagName, "other");
            String missingPermissionId = createLaunchTemplate(root, missingPermissionName, "floci");

            SessionCredentials allowed = createVersionSession(REGION, "floci", true);
            SessionCredentials missingPermission = createVersionSession(REGION, "floci", false);
            try (Ec2Client allowedClient = ec2Client(allowed);
                    Ec2Client missingPermissionClient = ec2Client(missingPermission)) {
                var byIdVersion = allowedClient.createLaunchTemplateVersion(request -> request
                        .launchTemplateId(byId)
                        .sourceVersion("1")
                        .launchTemplateData(data -> data.instanceType(InstanceType.T3_SMALL)))
                        .launchTemplateVersion();
                assertEquals(2L, byIdVersion.versionNumber());
                assertEquals(InstanceType.T3_SMALL,
                        root.describeLaunchTemplateVersions(request -> request
                                        .launchTemplateId(byId)
                                        .versions("2"))
                                .launchTemplateVersions().getFirst().launchTemplateData().instanceType());

                var byNameVersion = allowedClient.createLaunchTemplateVersion(request -> request
                        .launchTemplateName(byNameName)
                        .sourceVersion("1")
                        .launchTemplateData(data -> data.instanceType(InstanceType.T3_NANO)))
                        .launchTemplateVersion();
                assertEquals(2L, byNameVersion.versionNumber());
                assertEquals(2L, latestVersionNumber(root, null, byNameName));

                Ec2Exception wrongTag = assertThrows(Ec2Exception.class,
                        () -> allowedClient.createLaunchTemplateVersion(request -> request
                                .launchTemplateId(wrongTagId)
                                .sourceVersion("1")
                                .launchTemplateData(data -> data.instanceType(InstanceType.T3_SMALL))));
                assertAccessDenied(wrongTag, "ec2:CreateLaunchTemplateVersion");
                assertEquals(1L, latestVersionNumber(root, wrongTagId, null));

                Ec2Exception denied = assertThrows(Ec2Exception.class,
                        () -> missingPermissionClient.createLaunchTemplateVersion(request -> request
                                .launchTemplateId(missingPermissionId)
                                .sourceVersion("1")
                                .launchTemplateData(data -> data.instanceType(InstanceType.T3_SMALL))));
                assertAccessDenied(denied, "ec2:CreateLaunchTemplateVersion");
                assertEquals(1L, latestVersionNumber(root, missingPermissionId, null));
            }
        }
    }

    @Test
    void authorizesDefaultVersionModificationAgainstExistingTemplateArnAndResourceTagsWithSdk() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String byIdName = "modify-by-id-" + suffix;
        String byNameName = "modify-by-name-" + suffix;
        String wrongTagName = "modify-wrong-tag-" + suffix;
        String missingPermissionName = "modify-missing-permission-" + suffix;

        try (Ec2Client root = ec2Client(ACCOUNT_ID, "test-secret-key", null)) {
            String byId = createLaunchTemplateWithSecondVersion(root, byIdName, "floci");
            createLaunchTemplateWithSecondVersion(root, byNameName, "floci");
            String wrongTagId = createLaunchTemplateWithSecondVersion(root, wrongTagName, "other");
            String missingPermissionId = createLaunchTemplateWithSecondVersion(
                    root, missingPermissionName, "floci");

            SessionCredentials allowed = createModifySession(REGION, "floci", true);
            SessionCredentials missingPermission = createModifySession(REGION, "floci", false);
            try (Ec2Client allowedClient = ec2Client(allowed);
                    Ec2Client missingPermissionClient = ec2Client(missingPermission)) {
                assertEquals(2L, allowedClient.modifyLaunchTemplate(request -> request
                                .launchTemplateId(byId)
                                .defaultVersion("2"))
                        .launchTemplate().defaultVersionNumber());
                assertEquals(2L, defaultVersionNumber(root, byId, null));

                assertEquals(2L, allowedClient.modifyLaunchTemplate(request -> request
                                .launchTemplateName(byNameName)
                                .defaultVersion("2"))
                        .launchTemplate().defaultVersionNumber());
                assertEquals(2L, defaultVersionNumber(root, null, byNameName));

                Ec2Exception wrongTag = assertThrows(Ec2Exception.class,
                        () -> allowedClient.modifyLaunchTemplate(request -> request
                                .launchTemplateId(wrongTagId)
                                .defaultVersion("2")));
                assertAccessDenied(wrongTag, "ec2:ModifyLaunchTemplate");
                assertEquals(1L, defaultVersionNumber(root, wrongTagId, null));

                Ec2Exception denied = assertThrows(Ec2Exception.class,
                        () -> missingPermissionClient.modifyLaunchTemplate(request -> request
                                .launchTemplateId(missingPermissionId)
                                .defaultVersion("2")));
                assertAccessDenied(denied, "ec2:ModifyLaunchTemplate");
                assertEquals(1L, defaultVersionNumber(root, missingPermissionId, null));
            }
        }
    }

    private static SessionCredentials createModifySession(
            String policyRegion, String managedBy, boolean allowModification) {
        String roleName = "LaunchTemplateModifyRole" + UUID.randomUUID().toString().substring(0, 8);
        createRole(roleName);
        if (allowModification) {
            putRolePolicy(roleName, """
                    {
                      "Version": "2012-10-17",
                      "Statement": [{
                        "Effect": "Allow",
                        "Action": "ec2:ModifyLaunchTemplate",
                        "Resource": "arn:aws:ec2:%s:%s:launch-template/*",
                        "Condition": {"StringEquals": {
                          "aws:RequestedRegion": "%s",
                          "aws:ResourceTag/example.io:definition-id": "example",
                          "aws:ResourceTag/example.io:managed-by": "%s"
                        }}
                      }]
                    }
                    """.formatted(policyRegion, ACCOUNT_ID, policyRegion, managedBy));
        }
        return assumeRole(roleName);
    }

    private static SessionCredentials createVersionSession(
            String policyRegion, String managedBy, boolean allowVersionCreation) {
        String roleName = "LaunchTemplateVersionRole" + UUID.randomUUID().toString().substring(0, 8);
        createRole(roleName);
        if (allowVersionCreation) {
            putRolePolicy(roleName, """
                    {
                      "Version": "2012-10-17",
                      "Statement": [{
                        "Effect": "Allow",
                        "Action": "ec2:CreateLaunchTemplateVersion",
                        "Resource": "arn:aws:ec2:%s:%s:launch-template/*",
                        "Condition": {"StringEquals": {
                          "aws:RequestedRegion": "%s",
                          "aws:ResourceTag/example.io:definition-id": "example",
                          "aws:ResourceTag/example.io:managed-by": "%s"
                        }}
                      }]
                    }
                    """.formatted(policyRegion, ACCOUNT_ID, policyRegion, managedBy));
        }
        return assumeRole(roleName);
    }

    private static String createLaunchTemplate(Ec2Client client, String name, String managedBy) {
        return client.createLaunchTemplate(request -> request
                        .launchTemplateName(name)
                        .launchTemplateData(data -> data
                                .imageId("ami-0abcdef1234567890")
                                .instanceType(InstanceType.T3_MICRO))
                        .tagSpecifications(TagSpecification.builder()
                                .resourceType(ResourceType.LAUNCH_TEMPLATE)
                                .tags(
                                        Tag.builder().key("example.io:definition-id").value("example").build(),
                                        Tag.builder().key("example.io:managed-by").value(managedBy).build())
                                .build()))
                .launchTemplate().launchTemplateId();
    }

    private static String createLaunchTemplateWithSecondVersion(
            Ec2Client client, String name, String managedBy) {
        String id = createLaunchTemplate(client, name, managedBy);
        client.createLaunchTemplateVersion(request -> request
                .launchTemplateId(id)
                .sourceVersion("1")
                .launchTemplateData(data -> data.instanceType(InstanceType.T3_SMALL)));
        return id;
    }

    private static long defaultVersionNumber(Ec2Client client, String id, String name) {
        return client.describeLaunchTemplates(request -> {
                    if (id != null) {
                        request.launchTemplateIds(id);
                    }
                    if (name != null) {
                        request.launchTemplateNames(name);
                    }
                })
                .launchTemplates().getFirst().defaultVersionNumber();
    }

    private static long latestVersionNumber(Ec2Client client, String id, String name) {
        return client.describeLaunchTemplateVersions(request -> {
                    if (id != null) {
                        request.launchTemplateId(id);
                    }
                    if (name != null) {
                        request.launchTemplateName(name);
                    }
                    request.versions("$Latest");
                })
                .launchTemplateVersions().getFirst().versionNumber();
    }

    private static Ec2Client ec2Client(SessionCredentials credentials) {
        return ec2Client(
                credentials.accessKeyId(), credentials.secretAccessKey(), credentials.sessionToken());
    }

    private static Ec2Client ec2Client(String accessKeyId, String secretAccessKey, String sessionToken) {
        var credentials = sessionToken == null
                ? AwsBasicCredentials.create(accessKeyId, secretAccessKey)
                : AwsSessionCredentials.create(accessKeyId, secretAccessKey, sessionToken);
        return Ec2Client.builder()
                .endpointOverride(URI.create("http://localhost:" + RestAssured.port))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .build();
    }

    private static void assertAccessDenied(Ec2Exception exception, String action) {
        assertEquals(403, exception.statusCode());
        assertEquals("UnauthorizedOperation", exception.awsErrorDetails().errorCode());
        assertTrue(exception.getMessage().contains(action));
        assertNotNull(exception.requestId());
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
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SecretAccessKey"),
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

    private record SessionCredentials(String accessKeyId, String secretAccessKey, String sessionToken) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
