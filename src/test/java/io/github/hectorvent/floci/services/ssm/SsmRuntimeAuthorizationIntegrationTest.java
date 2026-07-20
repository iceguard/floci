package io.github.hectorvent.floci.services.ssm;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

@QuarkusTest
@TestProfile(SsmRuntimeAuthorizationIntegrationTest.IamEnforcementProfile.class)
class SsmRuntimeAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";
    private static final String AWS_DOCUMENT = "AWS-RunShellScript";

    @BeforeAll
    static void configureAwsJsonProtocol() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void authorizesEveryTaggedEc2TargetAndAwsDocument() {
        String firstInstanceId = createInstance("example", "floci");
        String secondInstanceId = createInstance("example", "floci");
        SessionCredentials credentials = createSession(
                ec2InstanceArn("*"), awsDocumentArn(AWS_DOCUMENT), true);

        sendCommand(credentials, instanceIds(firstInstanceId, secondInstanceId), AWS_DOCUMENT)
                .statusCode(200)
                .body("Command.CommandId", notNullValue());
    }

    @Test
    void authorizesManagedInstanceAndAccountOwnedDocument() {
        String managedInstanceId = "mi-" + randomSuffix();
        String documentName = "AccountRunbook" + randomSuffix();
        SessionCredentials credentials = createSession(
                managedInstanceArn(managedInstanceId), customDocumentArn(documentName), false);

        sendCommand(credentials, instanceIds(managedInstanceId), documentName)
                .statusCode(200)
                .body("Command.CommandId", notNullValue());
    }

    @Test
    void rejectsTargetWithMismatchedPersistedTag() {
        String instanceId = createInstance("example", "other");
        SessionCredentials credentials = createSession(
                ec2InstanceArn("*"), awsDocumentArn(AWS_DOCUMENT), true);

        assertAccessDenied(sendCommand(credentials, instanceIds(instanceId), AWS_DOCUMENT));
    }

    @Test
    void rejectsWhenAnyTargetResourceIsUnauthorized() {
        String allowedInstanceId = createInstance("example", "floci");
        String deniedInstanceId = createInstance("example", "floci");
        SessionCredentials credentials = createSession(
                ec2InstanceArn(allowedInstanceId), awsDocumentArn(AWS_DOCUMENT), true);

        assertAccessDenied(sendCommand(
                credentials, instanceIds(allowedInstanceId, deniedInstanceId), AWS_DOCUMENT));
    }

    @Test
    void rejectsManagedInstanceInWrongAccount() {
        String managedInstanceId = "mi-" + randomSuffix();
        SessionCredentials credentials = createSession(
                "arn:aws:ssm:" + REGION + ":999900001111:managed-instance/" + managedInstanceId,
                awsDocumentArn(AWS_DOCUMENT), false);

        assertAccessDenied(sendCommand(
                credentials, instanceIds(managedInstanceId), AWS_DOCUMENT));
    }

    @Test
    void rejectsManagedInstanceWhenPolicyAllowsEc2ResourceType() {
        String managedInstanceId = "mi-" + randomSuffix();
        SessionCredentials credentials = createSession(
                ec2InstanceArn("*"), awsDocumentArn(AWS_DOCUMENT), false);

        assertAccessDenied(sendCommand(
                credentials, instanceIds(managedInstanceId), AWS_DOCUMENT));
    }

    @Test
    void rejectsUnauthorizedAwsDocument() {
        String instanceId = createInstance("example", "floci");
        SessionCredentials credentials = createSession(
                ec2InstanceArn("*"), awsDocumentArn("AWS-RunPowerShellScript"), true);

        assertAccessDenied(sendCommand(credentials, instanceIds(instanceId), AWS_DOCUMENT));
    }

    @Test
    void rejectsCustomDocumentWhenOnlyAwsDocumentIsAllowed() {
        String instanceId = createInstance("example", "floci");
        SessionCredentials credentials = createSession(
                ec2InstanceArn("*"), awsDocumentArn(AWS_DOCUMENT), true);

        assertAccessDenied(sendCommand(
                credentials, instanceIds(instanceId), "AccountRunbook" + randomSuffix()));
    }

    @Test
    void rejectsMissingTargetPermission() {
        String instanceId = createInstance("example", "floci");
        SessionCredentials credentials = createSession(null, awsDocumentArn(AWS_DOCUMENT), false);

        assertAccessDenied(sendCommand(credentials, instanceIds(instanceId), AWS_DOCUMENT));
    }

    @Test
    void authorizesTagSelectedTargetsBeforeExistingCommandValidation() {
        createInstance("example", "tag-selector");
        SessionCredentials credentials = createSession(
                ec2InstanceArn("*"), awsDocumentArn(AWS_DOCUMENT), true, "tag-selector");

        sendCommand(credentials, tagTargets("example.io:managed-by", "tag-selector"), AWS_DOCUMENT)
                .statusCode(400)
                .body("__type", equalTo("InvalidInstanceId"));
    }

    @Test
    void rejectsTagSelectedTargetWithMismatchedConditionTag() {
        createInstance("other", "mismatched-selector");
        SessionCredentials credentials = createSession(
                ec2InstanceArn("*"), awsDocumentArn(AWS_DOCUMENT), true, "mismatched-selector");

        assertAccessDenied(sendCommand(
                credentials, tagTargets("example.io:managed-by", "mismatched-selector"), AWS_DOCUMENT));
    }

    private static SessionCredentials createSession(
            String targetResource, String documentResource, boolean requireTargetTags) {
        return createSession(targetResource, documentResource, requireTargetTags, "floci");
    }

    private static SessionCredentials createSession(
            String targetResource, String documentResource,
            boolean requireTargetTags, String expectedManagedBy) {
        String suffix = randomSuffix();
        String roleName = "SsmCommandOperator" + suffix;
        createRole(roleName);

        String targetCondition = requireTargetTags ? """
                ,
                  "Condition": {
                    "StringEquals": {
                      "ssm:resourceTag/example.io:definition-id": "example",
                      "ssm:resourceTag/example.io:managed-by": "%s"
                    }
                  }
                """.formatted(expectedManagedBy) : "";
        String targetStatement = targetResource == null ? "" : """
                {
                  "Effect": "Allow",
                  "Action": "ssm:SendCommand",
                  "Resource": "%s"%s
                }
                """.formatted(targetResource, targetCondition);
        String separator = targetStatement.isBlank() ? "" : ",";
        putRolePolicy(roleName, """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    %s%s
                    {
                      "Effect": "Allow",
                      "Action": "ssm:SendCommand",
                      "Resource": "%s"
                    }
                  ]
                }
                """.formatted(targetStatement, separator, documentResource));
        return assumeRole(roleName);
    }

    private static String createInstance(String definitionId, String managedBy) {
        return given()
                .formParam("Action", "RunInstances")
                .formParam("ImageId", "ami-amazonlinux2023")
                .formParam("InstanceType", "t2.micro")
                .formParam("MinCount", "1")
                .formParam("MaxCount", "1")
                .formParam("TagSpecification.1.ResourceType", "instance")
                .formParam("TagSpecification.1.Tag.1.Key", "example.io:definition-id")
                .formParam("TagSpecification.1.Tag.1.Value", definitionId)
                .formParam("TagSpecification.1.Tag.2.Key", "example.io:managed-by")
                .formParam("TagSpecification.1.Tag.2.Value", managedBy)
                .header("Authorization", auth(ACCOUNT_ID, "ec2"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract()
                .path("RunInstancesResponse.instancesSet.item.instanceId");
    }

    private static ValidatableResponse sendCommand(
            SessionCredentials credentials, String targetMembers, String documentName) {
        return given()
                .header("X-Amz-Target", "AmazonSSM.SendCommand")
                .contentType("application/x-amz-json-1.1")
                .body("""
                        {
                          %s,
                          "DocumentName": "%s",
                          "Parameters": {"commands": ["echo authorized"]}
                        }
                        """.formatted(targetMembers, documentName))
                .header("Authorization", auth(credentials.accessKeyId(), "ssm"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
        .when()
                .post("/")
        .then();
    }

    private static String instanceIds(String... instanceIds) {
        return "\"InstanceIds\": [\"" + String.join("\", \"", instanceIds) + "\"]";
    }

    private static String tagTargets(String tagKey, String tagValue) {
        return """
                "Targets": [{"Key": "tag:%s", "Values": ["%s"]}]
                """.formatted(tagKey, tagValue);
    }

    private static void assertAccessDenied(ValidatableResponse response) {
        response.statusCode(403)
                .body("__type", equalTo("AccessDeniedException"))
                .body("message", containsString("ssm:SendCommand"));
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
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
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static void putRolePolicy(String roleName, String policyDocument) {
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "ScopedSsmSendCommand")
                .formParam("PolicyDocument", policyDocument)
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        var response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "ssm-runtime-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, "sts"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract()
                .response();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private record SessionCredentials(String accessKeyId, String sessionToken) {}

    private static String ec2InstanceArn(String instanceId) {
        return "arn:aws:ec2:" + REGION + ":" + ACCOUNT_ID + ":instance/" + instanceId;
    }

    private static String managedInstanceArn(String instanceId) {
        return "arn:aws:ssm:" + REGION + ":" + ACCOUNT_ID + ":managed-instance/" + instanceId;
    }

    private static String awsDocumentArn(String documentName) {
        return "arn:aws:ssm:" + REGION + "::document/" + documentName;
    }

    private static String customDocumentArn(String documentName) {
        return "arn:aws:ssm:" + REGION + ":" + ACCOUNT_ID + ":document/" + documentName;
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private static String randomSuffix() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.ec2.mock", "true");
        }
    }
}
