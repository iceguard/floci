package io.github.hectorvent.floci.services.autoscaling;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(AutoScalingRuntimeAuthorizationIntegrationTest.IamEnforcementProfile.class)
class AutoScalingRuntimeAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";

    @Test
    void authorizesFutureAutoScalingGroupArnAndRequestTags() {
        Fixture fixture = createFixture();

        createAutoScalingGroup(
                fixture.credentials(), fixture.launchConfigurationName(),
                fixture.allowedName(), "floci")
                .statusCode(200)
                .body(containsString("CreateAutoScalingGroupResponse"));
    }

    @Test
    void rejectsAutoScalingGroupOutsideAuthorizedNameScope() {
        Fixture fixture = createFixture();

        createAutoScalingGroup(
                fixture.credentials(), fixture.launchConfigurationName(),
                fixture.deniedName(), "floci")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:CreateAutoScalingGroup"));
    }

    @Test
    void rejectsMismatchedAutoScalingGroupRequestTags() {
        Fixture fixture = createFixture();

        createAutoScalingGroup(
                fixture.credentials(), fixture.launchConfigurationName(),
                fixture.allowedName(), "other")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:CreateAutoScalingGroup"));
    }

    @Test
    void authorizesTagUpdatesAgainstExactGroupArnAndPersistedTags() {
        Fixture fixture = createFixture();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);

        describeAutoScalingGroup(fixture.allowedName())
                .statusCode(200)
                .body("DescribeAutoScalingGroupsResponse.DescribeAutoScalingGroupsResult"
                                + ".AutoScalingGroups.member.AutoScalingGroupARN",
                        startsWith("arn:aws:autoscaling:" + REGION + ":" + ACCOUNT_ID
                                + ":autoScalingGroup:"))
                .body("DescribeAutoScalingGroupsResponse.DescribeAutoScalingGroupsResult"
                                + ".AutoScalingGroups.member.AutoScalingGroupARN",
                        containsString(":autoScalingGroupName/" + fixture.allowedName()));
        createOrUpdateTags(fixture.credentials(), fixture.allowedName(), "approved")
                .statusCode(200)
                .body(containsString("CreateOrUpdateTagsResponse"));
    }

    @Test
    void rejectsTagUpdatesOutsideAuthorizedGroupScope() {
        Fixture fixture = createFixture();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.deniedName(), "floci").statusCode(200);

        createOrUpdateTags(fixture.credentials(), fixture.deniedName(), "approved")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:CreateOrUpdateTags"));
    }

    @Test
    void rejectsTagUpdatesWithMismatchedPersistedTags() {
        Fixture fixture = createFixture();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "other").statusCode(200);

        createOrUpdateTags(fixture.credentials(), fixture.allowedName(), "approved")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:CreateOrUpdateTags"));
    }

    @Test
    void rejectsTagUpdatesWithMismatchedRequestTags() {
        Fixture fixture = createFixture();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);

        createOrUpdateTags(fixture.credentials(), fixture.allowedName(), "denied")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:CreateOrUpdateTags"));
    }

    @Test
    void rejectsTagUpdatesWithoutPermission() {
        Fixture fixture = createFixture(false);
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);

        createOrUpdateTags(fixture.credentials(), fixture.allowedName(), "approved")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:CreateOrUpdateTags"));
    }

    @Test
    void authorizesEveryGroupInMultiResourceTagRequest() {
        Fixture fixture = createFixture();
        String secondAllowedName = fixture.allowedName() + "-second";
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                secondAllowedName, "floci").statusCode(200);

        createOrUpdateTags(
                fixture.credentials(), fixture.allowedName(), secondAllowedName, "approved")
                .statusCode(200)
                .body(containsString("CreateOrUpdateTagsResponse"));
        describeAutoScalingGroup(fixture.allowedName())
                .body(containsString("<Key>example.io:change</Key>"));
        describeAutoScalingGroup(secondAllowedName)
                .body(containsString("<Key>example.io:change</Key>"));
    }

    @Test
    void rejectsMultiResourceTagRequestWhenAnyGroupIsUnauthorized() {
        Fixture fixture = createFixture();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.deniedName(), "floci").statusCode(200);

        createOrUpdateTags(
                fixture.credentials(), fixture.allowedName(), fixture.deniedName(), "approved")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:CreateOrUpdateTags"));
        describeAutoScalingGroup(fixture.allowedName())
                .body(not(containsString("<Key>example.io:change</Key>")));
        describeAutoScalingGroup(fixture.deniedName())
                .body(not(containsString("<Key>example.io:change</Key>")));
    }

    @Test
    void authorizesGroupDeletionAgainstExactArnAndPersistedTags() {
        Fixture fixture = createFixture();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);

        deleteAutoScalingGroup(fixture.credentials(), fixture.allowedName())
                .statusCode(200)
                .body(containsString("DeleteAutoScalingGroupResponse"));
    }

    @Test
    void rejectsGroupDeletionOutsideAuthorizedResourceScope() {
        Fixture fixture = createFixture();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.deniedName(), "floci").statusCode(200);

        deleteAutoScalingGroup(fixture.credentials(), fixture.deniedName())
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:DeleteAutoScalingGroup"));
        describeAutoScalingGroup(fixture.deniedName()).statusCode(200);
    }

    @Test
    void rejectsGroupDeletionWithMismatchedPersistedTags() {
        Fixture fixture = createFixture();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "other").statusCode(200);

        deleteAutoScalingGroup(fixture.credentials(), fixture.allowedName())
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:DeleteAutoScalingGroup"));
        describeAutoScalingGroup(fixture.allowedName()).statusCode(200);
    }

    @Test
    void rejectsGroupDeletionWithoutPermission() {
        Fixture fixture = createFixture(true, false);
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);

        deleteAutoScalingGroup(fixture.credentials(), fixture.allowedName())
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:DeleteAutoScalingGroup"));
        describeAutoScalingGroup(fixture.allowedName()).statusCode(200);
    }

    @Test
    void authorizesScalingPolicyMutationsAgainstExactGroupArnAndPersistedTags() {
        Fixture fixture = createFixture();
        String policyName = "runtime-policy-" + fixture.allowedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);

        putScalingPolicy(fixture.credentials(), fixture.allowedName(), policyName)
                .statusCode(200)
                .body("PutScalingPolicyResponse.PutScalingPolicyResult.PolicyARN",
                        containsString(policyName));
        deleteScalingPolicy(fixture.credentials(), fixture.allowedName(), policyName)
                .statusCode(200)
                .body(containsString("DeletePolicyResponse"));
        describeScalingPolicy(fixture.allowedName(), policyName)
                .statusCode(200)
                .body(containsString("<ScalingPolicies></ScalingPolicies>"));
    }

    @Test
    void rejectsScalingPolicyMutationOutsideAuthorizedGroupScope() {
        Fixture fixture = createFixture();
        String policyName = "runtime-policy-" + fixture.deniedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.deniedName(), "floci").statusCode(200);

        putScalingPolicy(fixture.credentials(), fixture.deniedName(), policyName)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:PutScalingPolicy"));
        describeScalingPolicy(fixture.deniedName(), policyName)
                .statusCode(200)
                .body(containsString("<ScalingPolicies></ScalingPolicies>"));
    }

    @Test
    void rejectsScalingPolicyMutationWithMismatchedPersistedTags() {
        Fixture fixture = createFixture();
        String policyName = "runtime-policy-" + fixture.allowedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "other").statusCode(200);

        putScalingPolicy(fixture.credentials(), fixture.allowedName(), policyName)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:PutScalingPolicy"));
        describeScalingPolicy(fixture.allowedName(), policyName)
                .statusCode(200)
                .body(containsString("<ScalingPolicies></ScalingPolicies>"));
    }

    @Test
    void rejectsScalingPolicyMutationWithoutPermission() {
        Fixture fixture = createFixture(true, true, false);
        String policyName = "runtime-policy-" + fixture.allowedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);

        putScalingPolicy(fixture.credentials(), fixture.allowedName(), policyName)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:PutScalingPolicy"));
        describeScalingPolicy(fixture.allowedName(), policyName)
                .statusCode(200)
                .body(containsString("<ScalingPolicies></ScalingPolicies>"));
    }

    @Test
    void rejectsScalingPolicyDeletionOutsideAuthorizedGroupScope() {
        Fixture fixture = createFixture();
        String policyName = "runtime-policy-" + fixture.deniedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.deniedName(), "floci").statusCode(200);
        putScalingPolicy(ACCOUNT_ID, fixture.deniedName(), policyName).statusCode(200);

        deleteScalingPolicy(fixture.credentials(), fixture.deniedName(), policyName)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:DeletePolicy"));
        describeScalingPolicy(fixture.deniedName(), policyName)
                .statusCode(200)
                .body(containsString(policyName));
    }

    @Test
    void authorizesLifecycleHookMutationsAgainstExactGroupArnAndPersistedTags() {
        Fixture fixture = createFixture();
        String hookName = "runtime-hook-" + fixture.allowedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "floci").statusCode(200);

        putLifecycleHook(fixture.credentials(), fixture.allowedName(), hookName)
                .statusCode(200)
                .body(containsString("PutLifecycleHookResponse"));
        deleteLifecycleHook(fixture.credentials(), fixture.allowedName(), hookName)
                .statusCode(200)
                .body(containsString("DeleteLifecycleHookResponse"));
    }

    @Test
    void rejectsLifecycleHookMutationOutsideAuthorizedGroupScope() {
        Fixture fixture = createFixture();
        String hookName = "runtime-hook-" + fixture.deniedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.deniedName(), "floci").statusCode(200);

        putLifecycleHook(fixture.credentials(), fixture.deniedName(), hookName)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:PutLifecycleHook"));
    }

    @Test
    void rejectsLifecycleHookMutationWithMismatchedPersistedTags() {
        Fixture fixture = createFixture();
        String hookName = "runtime-hook-" + fixture.allowedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.allowedName(), "other").statusCode(200);

        putLifecycleHook(fixture.credentials(), fixture.allowedName(), hookName)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:PutLifecycleHook"));
    }

    @Test
    void rejectsLifecycleHookDeletionOutsideAuthorizedGroupScope() {
        Fixture fixture = createFixture();
        String hookName = "runtime-hook-" + fixture.deniedName();
        createAutoScalingGroup(
                ACCOUNT_ID, fixture.launchConfigurationName(),
                fixture.deniedName(), "floci").statusCode(200);
        putLifecycleHook(ACCOUNT_ID, fixture.deniedName(), hookName).statusCode(200);

        deleteLifecycleHook(fixture.credentials(), fixture.deniedName(), hookName)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("autoscaling:DeleteLifecycleHook"));
    }

    private static Fixture createFixture() {
        return createFixture(true, true);
    }

    private static Fixture createFixture(boolean allowTagUpdates) {
        return createFixture(allowTagUpdates, true);
    }

    private static Fixture createFixture(boolean allowTagUpdates, boolean allowDelete) {
        return createFixture(allowTagUpdates, allowDelete, true);
    }

    private static Fixture createFixture(
            boolean allowTagUpdates, boolean allowDelete, boolean allowPolicyMutations) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String roleName = "AutoScalingRuntimeOperator" + suffix;
        String launchConfigurationName = "runtime-lc-" + suffix;
        createLaunchConfiguration(launchConfigurationName);
        createRole(roleName);
        putRolePolicy(roleName, allowTagUpdates, allowDelete, allowPolicyMutations);
        return new Fixture(
                launchConfigurationName,
                "team-a-" + suffix,
                "team-b-" + suffix,
                assumeRole(roleName));
    }

    private static void createLaunchConfiguration(String launchConfigurationName) {
        given()
                .formParam("Action", "CreateLaunchConfiguration")
                .formParam("LaunchConfigurationName", launchConfigurationName)
                .formParam("ImageId", "ami-12345678")
                .formParam("InstanceType", "t3.micro")
                .header("Authorization", auth(ACCOUNT_ID, "autoscaling"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
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

    private static void putRolePolicy(
            String roleName, boolean allowTagUpdates, boolean allowDelete,
            boolean allowPolicyMutations) {
        String tagUpdateStatement = allowTagUpdates ? """
                , {
                  "Effect": "Allow",
                  "Action": "autoscaling:CreateOrUpdateTags",
                  "Resource": "arn:aws:autoscaling:%s:%s:autoScalingGroup:*:autoScalingGroupName/team-a-*",
                  "Condition": {
                    "StringEquals": {
                      "aws:ResourceTag/example.io:definition-id": "example",
                      "aws:ResourceTag/example.io:managed-by": "floci",
                      "aws:RequestTag/example.io:change": "approved"
                    }
                  }
                }
                """.formatted(REGION, ACCOUNT_ID) : "";
        String deleteStatement = allowDelete ? """
                , {
                  "Effect": "Allow",
                  "Action": "autoscaling:DeleteAutoScalingGroup",
                  "Resource": "arn:aws:autoscaling:%s:%s:autoScalingGroup:*:autoScalingGroupName/team-a-*",
                  "Condition": {
                    "StringEquals": {
                      "aws:ResourceTag/example.io:definition-id": "example",
                      "aws:ResourceTag/example.io:managed-by": "floci",
                      "aws:RequestedRegion": "%s"
                    }
                  }
                }
                """.formatted(REGION, ACCOUNT_ID, REGION) : "";
        String policyMutationStatement = allowPolicyMutations ? """
                , {
                  "Effect": "Allow",
                  "Action": [
                    "autoscaling:PutLifecycleHook",
                    "autoscaling:DeleteLifecycleHook",
                    "autoscaling:PutScalingPolicy",
                    "autoscaling:DeletePolicy"
                  ],
                  "Resource": "arn:aws:autoscaling:%s:%s:autoScalingGroup:*:autoScalingGroupName/team-a-*",
                  "Condition": {
                    "StringEquals": {
                      "aws:ResourceTag/example.io:definition-id": "example",
                      "aws:ResourceTag/example.io:managed-by": "floci",
                      "aws:RequestedRegion": "%s"
                    }
                  }
                }
                """.formatted(REGION, ACCOUNT_ID, REGION) : "";
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "ScopedAutoScalingRuntimeAuthorization")
                .formParam("PolicyDocument", """
                        {
                          "Version": "2012-10-17",
                          "Statement": [{
                            "Effect": "Allow",
                            "Action": "autoscaling:CreateAutoScalingGroup",
                            "Resource": "arn:aws:autoscaling:%s:%s:autoScalingGroup:*:autoScalingGroupName/team-a-*",
                            "Condition": {
                              "StringEquals": {
                                "aws:RequestTag/example.io:definition-id": "example",
                                "aws:RequestTag/example.io:managed-by": "floci"
                              }
                            }
                          }%s%s%s]
                        }
                        """.formatted(
                                REGION, ACCOUNT_ID, tagUpdateStatement, deleteStatement,
                                policyMutationStatement))
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        io.restassured.response.Response response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "autoscaling-runtime-authorization-test")
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

    private static io.restassured.response.ValidatableResponse createAutoScalingGroup(
            String accessKeyId, String launchConfigurationName, String name, String managedBy) {
        return createAutoScalingGroup(
                authorizedRequest(accessKeyId), launchConfigurationName, name, managedBy);
    }

    private static io.restassured.response.ValidatableResponse createAutoScalingGroup(
            SessionCredentials credentials, String launchConfigurationName, String name,
            String managedBy) {
        return createAutoScalingGroup(
                authorizedRequest(credentials), launchConfigurationName, name, managedBy);
    }

    private static io.restassured.response.ValidatableResponse createAutoScalingGroup(
            io.restassured.specification.RequestSpecification request,
            String launchConfigurationName, String name, String managedBy) {
        return request
                .formParam("Action", "CreateAutoScalingGroup")
                .formParam("AutoScalingGroupName", name)
                .formParam("LaunchConfigurationName", launchConfigurationName)
                .formParam("MinSize", "0")
                .formParam("MaxSize", "1")
                .formParam("DesiredCapacity", "0")
                .formParam("AvailabilityZones.member.1", REGION + "a")
                .formParam("Tags.member.1.Key", "example.io:definition-id")
                .formParam("Tags.member.1.Value", "example")
                .formParam("Tags.member.2.Key", "example.io:managed-by")
                .formParam("Tags.member.2.Value", managedBy)
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse createOrUpdateTags(
            SessionCredentials credentials, String name, String change) {
        return authorizedRequest(credentials)
                .formParam("Action", "CreateOrUpdateTags")
                .formParam("Tags.member.1.ResourceId", name)
                .formParam("Tags.member.1.ResourceType", "auto-scaling-group")
                .formParam("Tags.member.1.Key", "example.io:change")
                .formParam("Tags.member.1.Value", change)
                .formParam("Tags.member.1.PropagateAtLaunch", "false")
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse createOrUpdateTags(
            SessionCredentials credentials, String firstName, String secondName, String change) {
        return authorizedRequest(credentials)
                .formParam("Action", "CreateOrUpdateTags")
                .formParam("Tags.member.1.ResourceId", firstName)
                .formParam("Tags.member.1.ResourceType", "auto-scaling-group")
                .formParam("Tags.member.1.Key", "example.io:change")
                .formParam("Tags.member.1.Value", change)
                .formParam("Tags.member.1.PropagateAtLaunch", "false")
                .formParam("Tags.member.2.ResourceId", secondName)
                .formParam("Tags.member.2.ResourceType", "auto-scaling-group")
                .formParam("Tags.member.2.Key", "example.io:change")
                .formParam("Tags.member.2.Value", change)
                .formParam("Tags.member.2.PropagateAtLaunch", "false")
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse describeAutoScalingGroup(String name) {
        return given()
                .formParam("Action", "DescribeAutoScalingGroups")
                .formParam("AutoScalingGroupNames.member.1", name)
                .header("Authorization", auth(ACCOUNT_ID, "autoscaling"))
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse deleteAutoScalingGroup(
            SessionCredentials credentials, String name) {
        return authorizedRequest(credentials)
                .formParam("Action", "DeleteAutoScalingGroup")
                .formParam("AutoScalingGroupName", name)
                .formParam("ForceDelete", "true")
        .when()
                .post("/")
                .then();
    }

    private static io.restassured.response.ValidatableResponse putScalingPolicy(
            String accessKeyId, String autoScalingGroupName, String policyName) {
        return putScalingPolicy(
                authorizedRequest(accessKeyId), autoScalingGroupName, policyName);
    }

    private static io.restassured.response.ValidatableResponse putScalingPolicy(
            SessionCredentials credentials, String autoScalingGroupName, String policyName) {
        return putScalingPolicy(
                authorizedRequest(credentials), autoScalingGroupName, policyName);
    }

    private static io.restassured.response.ValidatableResponse putScalingPolicy(
            io.restassured.specification.RequestSpecification request,
            String autoScalingGroupName, String policyName) {
        return request
                .formParam("Action", "PutScalingPolicy")
                .formParam("AutoScalingGroupName", autoScalingGroupName)
                .formParam("PolicyName", policyName)
                .formParam("PolicyType", "SimpleScaling")
                .formParam("AdjustmentType", "ChangeInCapacity")
                .formParam("ScalingAdjustment", "1")
        .when()
                .post("/")
                .then();
    }

    private static io.restassured.response.ValidatableResponse putLifecycleHook(
            String accessKeyId, String autoScalingGroupName, String lifecycleHookName) {
        return putLifecycleHook(
                authorizedRequest(accessKeyId), autoScalingGroupName, lifecycleHookName);
    }

    private static io.restassured.response.ValidatableResponse putLifecycleHook(
            SessionCredentials credentials, String autoScalingGroupName, String lifecycleHookName) {
        return putLifecycleHook(
                authorizedRequest(credentials), autoScalingGroupName, lifecycleHookName);
    }

    private static io.restassured.response.ValidatableResponse putLifecycleHook(
            io.restassured.specification.RequestSpecification request,
            String autoScalingGroupName, String lifecycleHookName) {
        return request
                .formParam("Action", "PutLifecycleHook")
                .formParam("AutoScalingGroupName", autoScalingGroupName)
                .formParam("LifecycleHookName", lifecycleHookName)
                .formParam("LifecycleTransition", "autoscaling:EC2_INSTANCE_TERMINATING")
                .formParam("HeartbeatTimeout", "300")
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse deleteLifecycleHook(
            SessionCredentials credentials, String autoScalingGroupName, String lifecycleHookName) {
        return authorizedRequest(credentials)
                .formParam("Action", "DeleteLifecycleHook")
                .formParam("AutoScalingGroupName", autoScalingGroupName)
                .formParam("LifecycleHookName", lifecycleHookName)
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse deleteScalingPolicy(
            SessionCredentials credentials, String autoScalingGroupName, String policyName) {
        return authorizedRequest(credentials)
                .formParam("Action", "DeletePolicy")
                .formParam("AutoScalingGroupName", autoScalingGroupName)
                .formParam("PolicyName", policyName)
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse describeScalingPolicy(
            String autoScalingGroupName, String policyName) {
        return given()
                .formParam("Action", "DescribePolicies")
                .formParam("AutoScalingGroupName", autoScalingGroupName)
                .formParam("PolicyNames.member.1", policyName)
                .header("Authorization", auth(ACCOUNT_ID, "autoscaling"))
        .when()
                .post("/")
        .then();
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private static io.restassured.specification.RequestSpecification authorizedRequest(
            String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "autoscaling"));
    }

    private static io.restassured.specification.RequestSpecification authorizedRequest(
            SessionCredentials credentials) {
        return authorizedRequest(credentials.accessKeyId())
                .header("X-Amz-Security-Token", credentials.sessionToken());
    }

    private record SessionCredentials(String accessKeyId, String sessionToken) {}

    private record Fixture(
            String launchConfigurationName, String allowedName,
            String deniedName, SessionCredentials credentials) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
