package io.github.hectorvent.floci.services.rds;

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
@TestProfile(RdsRuntimeAuthorizationIntegrationTest.IamEnforcementProfile.class)
class RdsRuntimeAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "333344445555";
    private static final String REGION = "us-east-1";
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
    void assumedRoleEnforcementUsesTheExactSubnetGroupArnAndRequestTags() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String allowedName = "allowed-subnet-group-" + suffix;
        String deniedName = "denied-subnet-group-" + suffix;
        String callerRole = "RdsProvisioner" + suffix;
        String allowedArn = subnetGroupArn(allowedName);

        String vpcId = createVpc("10.72.0.0/16");
        String subnetA = createSubnet(vpcId, "10.72.1.0/24", "us-east-1a");
        String subnetB = createSubnet(vpcId, "10.72.2.0/24", "us-east-1b");
        createRole(callerRole);
        putRolePolicy(callerRole, """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "rds:CreateDBSubnetGroup",
                    "Resource": "%s*",
                    "Condition": {
                      "StringEquals": {
                        "aws:RequestTag/example.io:managed-by": "floci",
                        "aws:RequestTag/example.io:definition-id": "sample"
                      }
                    }
                  }]
                }
                """.formatted(allowedArn));

        given()
                .formParam("Action", "SimulatePrincipalPolicy")
                .formParam("PolicySourceArn", roleArn(callerRole))
                .formParam("ActionNames.member.1", "rds:CreateDBSubnetGroup")
                .formParam("ResourceArns.member.1", allowedArn)
                .formParam("ContextEntries.member.1.ContextKeyName",
                        "aws:RequestTag/example.io:managed-by")
                .formParam("ContextEntries.member.1.ContextKeyValues.member.1", "floci")
                .formParam("ContextEntries.member.1.ContextKeyType", "string")
                .formParam("ContextEntries.member.2.ContextKeyName",
                        "aws:RequestTag/example.io:definition-id")
                .formParam("ContextEntries.member.2.ContextKeyValues.member.1", "sample")
                .formParam("ContextEntries.member.2.ContextKeyType", "string")
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("SimulatePrincipalPolicyResponse.SimulatePrincipalPolicyResult"
                                + ".EvaluationResults.member.EvalDecision",
                        equalTo("allowed"));

        SessionCredentials credentials = assumeRole(callerRole);
        createSubnetGroup(credentials, allowedName, subnetA, subnetB, "floci", "sample")
                .statusCode(200)
                .body(containsString("<DBSubnetGroupName>" + allowedName + "</DBSubnetGroupName>"));
        createSubnetGroup(credentials, deniedName, subnetA, subnetB, "floci", "sample")
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(containsString("rds:CreateDBSubnetGroup"));
        createSubnetGroup(credentials, allowedName + "-wrong-tag", subnetA, subnetB, "other", "sample")
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(containsString("rds:CreateDBSubnetGroup"));
    }

    @Test
    void assumedRoleEnforcementUsesPersistedDbInstanceTagsForMutationAndDelete() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String allowedPrefix = "tagged-db-" + suffix;
        String deleteName = allowedPrefix + "-delete";
        String modifyName = allowedPrefix + "-modify";
        String wrongTagName = allowedPrefix + "-wrong-tag";
        String wrongResourceName = "other-db-" + suffix;
        String callerRole = "RdsTagMutation" + suffix;

        createDbInstance(deleteName, "floci", "sample").statusCode(200);
        createDbInstance(modifyName, "floci", "sample").statusCode(200);
        createDbInstance(wrongTagName, "other", "sample").statusCode(200);
        createDbInstance(wrongResourceName, "floci", "sample").statusCode(200);
        createRole(callerRole);
        putRolePolicy(callerRole, """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": ["rds:DeleteDBInstance", "rds:ModifyDBInstance"],
                    "Resource": "%s*",
                    "Condition": {
                      "StringEquals": {
                        "aws:ResourceTag/example.io:managed-by": "floci",
                        "aws:ResourceTag/example.io:definition-id": "sample"
                      }
                    }
                  }]
                }
                """.formatted(dbInstanceArn(allowedPrefix)));

        SessionCredentials credentials = assumeRole(callerRole);
        modifyDbInstance(credentials, modifyName)
                .statusCode(200)
                .body(containsString("<DBInstanceIdentifier>" + modifyName + "</DBInstanceIdentifier>"));
        deleteDbInstance(credentials, deleteName)
                .statusCode(200)
                .body(containsString("<DBInstanceIdentifier>" + deleteName + "</DBInstanceIdentifier>"));
        deleteDbInstance(credentials, wrongTagName)
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(containsString("rds:DeleteDBInstance"));
        deleteDbInstance(credentials, wrongResourceName)
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(containsString("rds:DeleteDBInstance"));

        deleteDbInstance(ACCOUNT_ID, modifyName).statusCode(200);
        deleteDbInstance(ACCOUNT_ID, wrongTagName).statusCode(200);
        deleteDbInstance(ACCOUNT_ID, wrongResourceName).statusCode(200);
    }

    private static String createVpc(String cidr) {
        return given()
                .formParam("Action", "CreateVpc")
                .formParam("CidrBlock", cidr)
                .header("Authorization", auth(ACCOUNT_ID, "ec2"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract()
                .path("CreateVpcResponse.vpc.vpcId");
    }

    private static String createSubnet(String vpcId, String cidr, String availabilityZone) {
        return given()
                .formParam("Action", "CreateSubnet")
                .formParam("VpcId", vpcId)
                .formParam("CidrBlock", cidr)
                .formParam("AvailabilityZone", availabilityZone)
                .header("Authorization", auth(ACCOUNT_ID, "ec2"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract()
                .path("CreateSubnetResponse.subnet.subnetId");
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument", TRUST_POLICY)
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
                .formParam("PolicyName", "ScopedRdsProvisioning")
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
                .formParam("RoleArn", roleArn(roleName))
                .formParam("RoleSessionName", "rds-runtime-authorization")
                .header("Authorization", auth(ACCOUNT_ID, "sts"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static io.restassured.response.ValidatableResponse createSubnetGroup(
            SessionCredentials credentials, String name, String subnetA, String subnetB,
            String managedBy, String definitionId) {
        return given()
                .formParam("Action", "CreateDBSubnetGroup")
                .formParam("DBSubnetGroupName", name)
                .formParam("DBSubnetGroupDescription", "runtime authorization test")
                .formParam("SubnetIds.SubnetIdentifier.1", subnetA)
                .formParam("SubnetIds.SubnetIdentifier.2", subnetB)
                .formParam("Tags.member.1.Key", "example.io:managed-by")
                .formParam("Tags.member.1.Value", managedBy)
                .formParam("Tags.member.2.Key", "example.io:definition-id")
                .formParam("Tags.member.2.Value", definitionId)
                .header("Authorization", auth(credentials.accessKeyId(), "rds"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse createDbInstance(
            String name, String managedBy, String definitionId) {
        return given()
                .formParam("Action", "CreateDBInstance")
                .formParam("DBInstanceIdentifier", name)
                .formParam("Engine", "postgres")
                .formParam("MasterUsername", "admin")
                .formParam("MasterUserPassword", "test-password")
                .formParam("Tags.member.1.Key", "example.io:managed-by")
                .formParam("Tags.member.1.Value", managedBy)
                .formParam("Tags.member.2.Key", "example.io:definition-id")
                .formParam("Tags.member.2.Value", definitionId)
                .header("Authorization", auth(ACCOUNT_ID, "rds"))
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse modifyDbInstance(
            SessionCredentials credentials, String name) {
        return given()
                .formParam("Action", "ModifyDBInstance")
                .formParam("DBInstanceIdentifier", name)
                .formParam("AutoMinorVersionUpgrade", "false")
                .header("Authorization", auth(credentials.accessKeyId(), "rds"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse deleteDbInstance(
            String accessKeyId, String name) {
        return given()
                .formParam("Action", "DeleteDBInstance")
                .formParam("DBInstanceIdentifier", name)
                .formParam("SkipFinalSnapshot", "true")
                .header("Authorization", auth(accessKeyId, "rds"))
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse deleteDbInstance(
            SessionCredentials credentials, String name) {
        return given()
                .formParam("Action", "DeleteDBInstance")
                .formParam("DBInstanceIdentifier", name)
                .formParam("SkipFinalSnapshot", "true")
                .header("Authorization", auth(credentials.accessKeyId(), "rds"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
        .when()
                .post("/")
        .then();
    }

    private static String roleArn(String roleName) {
        return "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName;
    }

    private static String subnetGroupArn(String name) {
        return "arn:aws:rds:" + REGION + ":" + ACCOUNT_ID + ":subgrp:" + name;
    }

    private static String dbInstanceArn(String name) {
        return "arn:aws:rds:" + REGION + ":" + ACCOUNT_ID + ":db:" + name;
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private record SessionCredentials(String accessKeyId, String sessionToken) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.rds.mock", "true");
        }
    }
}
