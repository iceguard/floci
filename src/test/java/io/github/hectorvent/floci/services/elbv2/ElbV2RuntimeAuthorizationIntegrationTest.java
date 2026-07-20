package io.github.hectorvent.floci.services.elbv2;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(ElbV2RuntimeAuthorizationIntegrationTest.IamEnforcementProfile.class)
class ElbV2RuntimeAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";

    @Test
    void authorizesTheFutureTargetGroupArnRequestTagsAndAddTagsPermission() {
        Fixture fixture = createFixture(true);

        createTargetGroup(fixture.credentials(), fixture.allowedName(), "floci")
                .statusCode(200)
                .body("CreateTargetGroupResponse.CreateTargetGroupResult.TargetGroups.member.TargetGroupArn",
                        startsWith("arn:aws:elasticloadbalancing:" + REGION + ":" + ACCOUNT_ID
                                + ":targetgroup/" + fixture.allowedName() + "/"));
    }

    @Test
    void rejectsTaggedTargetGroupCreationWithoutAddTagsPermission() {
        Fixture fixture = createFixture(false);

        createTargetGroup(fixture.credentials(), fixture.allowedName(), "floci")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:AddTags"));
    }

    @Test
    void rejectsTargetGroupCreationOutsideNameOrTagScope() {
        Fixture fixture = createFixture(true);

        createTargetGroup(fixture.credentials(), fixture.deniedName(), "floci")
                .statusCode(403)
                .body(containsString("elasticloadbalancing:CreateTargetGroup"));
        createTargetGroup(fixture.credentials(), fixture.allowedName(), "other")
                .statusCode(403)
                .body(containsString("elasticloadbalancing:CreateTargetGroup"));
    }

    @Test
    void authorizesTargetGroupMutationAndDeletionFromPersistedResourceTags() {
        Fixture fixture = createFixture(true);
        String targetGroupArn = createTargetGroupArn(
                fixture.credentials(), fixture.allowedName(), "floci");

        modifyTargetGroupAttributes(fixture.credentials(), targetGroupArn).statusCode(200);
        deleteTargetGroup(fixture.credentials(), targetGroupArn).statusCode(200);
    }

    @Test
    void rejectsTargetGroupMutationWithWrongTagsAndDeletionWithWrongResource() {
        Fixture fixture = createFixture(true);
        String wrongTagsArn = createTargetGroupArn(ACCOUNT_ID, fixture.allowedName(), "other");
        String wrongResourceArn = createTargetGroupArn(ACCOUNT_ID, fixture.deniedName(), "floci");

        modifyTargetGroupAttributes(fixture.credentials(), wrongTagsArn)
                .statusCode(403)
                .body(containsString("elasticloadbalancing:ModifyTargetGroupAttributes"));
        deleteTargetGroup(fixture.credentials(), wrongResourceArn)
                .statusCode(403)
                .body(containsString("elasticloadbalancing:DeleteTargetGroup"));
        describeTargetGroup(wrongTagsArn).statusCode(200);
        describeTargetGroup(wrongResourceArn).statusCode(200);
    }

    @Test
    void authorizesListenerCreationFromReferencedLoadBalancerTags() {
        Fixture fixture = createFixture();
        String loadBalancerArn = createLoadBalancer(fixture.allowedName(), "floci");
        String targetGroupArn = createTargetGroupArn(
                ACCOUNT_ID, fixture.allowedName() + "-tg", "floci");

        createListener(fixture.credentials(), loadBalancerArn, targetGroupArn, "floci")
                .statusCode(200)
                .body("CreateListenerResponse.CreateListenerResult.Listeners.member.ListenerArn",
                        startsWith("arn:aws:elasticloadbalancing:" + REGION + ":" + ACCOUNT_ID
                                + ":listener/app/" + fixture.allowedName() + "/"));
    }

    @Test
    void rejectsListenerCreationOutsideAuthorizedResourceScope() {
        Fixture fixture = createFixture();
        String loadBalancerArn = createLoadBalancer(fixture.deniedName(), "floci");
        String targetGroupArn = createTargetGroupArn(
                ACCOUNT_ID, fixture.deniedName() + "-tg", "floci");

        createListener(fixture.credentials(), loadBalancerArn, targetGroupArn, "floci")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:CreateListener"));
    }

    @Test
    void rejectsListenerCreationWithMismatchedLoadBalancerTags() {
        Fixture fixture = createFixture();
        String loadBalancerArn = createLoadBalancer(fixture.allowedName(), "other");
        String targetGroupArn = createTargetGroupArn(
                ACCOUNT_ID, fixture.allowedName() + "-tg", "floci");

        createListener(fixture.credentials(), loadBalancerArn, targetGroupArn, "floci")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:CreateListener"));
    }

    @Test
    void rejectsTaggedListenerCreationWithoutAddTagsPermission() {
        Fixture fixture = createFixture(true, false, true);
        String loadBalancerArn = createLoadBalancer(fixture.allowedName(), "floci");
        String targetGroupArn = createTargetGroupArn(
                ACCOUNT_ID, fixture.allowedName() + "-tg", "floci");

        createListener(fixture.credentials(), loadBalancerArn, targetGroupArn, "floci")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:AddTags"));
    }

    @Test
    void authorizesListenerDeletionFromPersistedResourceTags() {
        Fixture fixture = createFixture();
        String listenerArn = createListenerArn(
                fixture.allowedName(), fixture.allowedName() + "-tg", "floci");

        deleteListener(fixture.credentials(), listenerArn).statusCode(200);
    }

    @Test
    void rejectsListenerDeletionOutsideTheAuthorizedResourceScope() {
        Fixture fixture = createFixture();
        String listenerArn = createListenerArn(
                fixture.deniedName(), fixture.deniedName() + "-tg", "floci");

        deleteListener(fixture.credentials(), listenerArn)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:DeleteListener"));
        describeListener(listenerArn).statusCode(200);
    }

    @Test
    void rejectsListenerDeletionWithMismatchedPersistedTags() {
        Fixture fixture = createFixture();
        String listenerArn = createListenerArn(
                fixture.allowedName(), fixture.allowedName() + "-tg", "other");

        deleteListener(fixture.credentials(), listenerArn)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:DeleteListener"));
        describeListener(listenerArn).statusCode(200);
    }

    @Test
    void rejectsListenerDeletionWithoutPermission() {
        Fixture fixture = createFixture(true, true, false);
        String listenerArn = createListenerArn(
                fixture.allowedName(), fixture.allowedName() + "-tg", "floci");

        deleteListener(fixture.credentials(), listenerArn)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:DeleteListener"));
        describeListener(listenerArn).statusCode(200);
    }

    @Test
    void authorizesLoadBalancerDeletionFromPersistedResourceTags() {
        Fixture fixture = createFixture(true);
        String loadBalancerArn = createLoadBalancer(fixture.allowedName(), "floci");

        deleteLoadBalancer(fixture.credentials(), loadBalancerArn).statusCode(200);
    }

    @Test
    void rejectsLoadBalancerDeletionWithWrongResourceOrPersistedTags() {
        Fixture fixture = createFixture(true);
        String wrongResourceArn = createLoadBalancer(fixture.deniedName(), "floci");
        String wrongTagsArn = createLoadBalancer(fixture.allowedName(), "other");

        deleteLoadBalancer(fixture.credentials(), wrongResourceArn)
                .statusCode(403)
                .body(containsString("elasticloadbalancing:DeleteLoadBalancer"));
        deleteLoadBalancer(fixture.credentials(), wrongTagsArn)
                .statusCode(403)
                .body(containsString("elasticloadbalancing:DeleteLoadBalancer"));
        describeLoadBalancer(wrongResourceArn).statusCode(200);
        describeLoadBalancer(wrongTagsArn).statusCode(200);
    }

    private static Fixture createFixture() {
        return createFixture(true, true, true);
    }

    private static Fixture createFixture(boolean allowAddTags) {
        return createFixture(allowAddTags, true, true);
    }

    private static Fixture createFixture(
            boolean allowAddTags, boolean allowListenerAddTags, boolean allowDeleteListener) {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String roleName = "ElbRuntimeOperator" + suffix;
        String allowedName = "team-a-" + suffix;
        String deniedName = "team-b-" + suffix;
        createRole(roleName);
        String addTagsStatement = allowAddTags ? """
                , {
                  "Effect": "Allow",
                  "Action": "elasticloadbalancing:AddTags",
                  "Resource": "arn:aws:elasticloadbalancing:%s:%s:targetgroup/team-a-*",
                  "Condition": {"StringEquals": {
                    "aws:RequestTag/example.io:definition-id": "example",
                    "aws:RequestTag/example.io:managed-by": "floci",
                    "elasticloadbalancing:CreateAction": "CreateTargetGroup"
                  }}
                }
                """.formatted(REGION, ACCOUNT_ID) : "";
        String listenerAddTagsStatement = allowListenerAddTags ? """
                , {
                  "Effect": "Allow",
                  "Action": "elasticloadbalancing:AddTags",
                  "Resource": "arn:aws:elasticloadbalancing:%s:%s:listener/app/team-a-*",
                  "Condition": {"StringEquals": {
                    "aws:RequestTag/example.io:definition-id": "example",
                    "aws:RequestTag/example.io:managed-by": "floci",
                    "elasticloadbalancing:CreateAction": "CreateListener"
                  }}
                }
                """.formatted(REGION, ACCOUNT_ID) : "";
        String deleteListenerStatement = allowDeleteListener ? """
                , {
                  "Effect": "Allow",
                  "Action": "elasticloadbalancing:DeleteListener",
                  "Resource": "arn:aws:elasticloadbalancing:%s:%s:listener/app/team-a-*",
                  "Condition": {"StringEquals": {
                    "aws:ResourceTag/example.io:definition-id": "example",
                    "aws:ResourceTag/example.io:managed-by": "floci"
                  }}
                }
                """.formatted(REGION, ACCOUNT_ID) : "";
        putRolePolicy(roleName, """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "elasticloadbalancing:CreateTargetGroup",
                    "Resource": "arn:aws:elasticloadbalancing:%s:%s:targetgroup/team-a-*",
                    "Condition": {"StringEquals": {
                      "aws:RequestTag/example.io:definition-id": "example",
                      "aws:RequestTag/example.io:managed-by": "floci"
                    }}
                  }%s, {
                    "Effect": "Allow",
                    "Action": [
                      "elasticloadbalancing:DeleteTargetGroup",
                      "elasticloadbalancing:ModifyTargetGroupAttributes"
                    ],
                    "Resource": "arn:aws:elasticloadbalancing:%s:%s:targetgroup/team-a-*",
                    "Condition": {"StringEquals": {
                      "aws:ResourceTag/example.io:definition-id": "example",
                      "aws:ResourceTag/example.io:managed-by": "floci"
                    }}
                  }, {
                    "Effect": "Allow",
                    "Action": "elasticloadbalancing:DeleteLoadBalancer",
                    "Resource": "arn:aws:elasticloadbalancing:%s:%s:loadbalancer/app/team-a-*",
                    "Condition": {"StringEquals": {
                      "aws:ResourceTag/example.io:definition-id": "example",
                      "aws:ResourceTag/example.io:managed-by": "floci"
                    }}
                  }, {
                    "Effect": "Allow",
                    "Action": "elasticloadbalancing:CreateListener",
                    "Resource": "arn:aws:elasticloadbalancing:%s:%s:loadbalancer/app/team-a-*",
                    "Condition": {"StringEquals": {
                      "aws:ResourceTag/example.io:definition-id": "example",
                      "aws:ResourceTag/example.io:managed-by": "floci"
                    }}
                  }%s%s]
                }
                """.formatted(
                        REGION, ACCOUNT_ID, addTagsStatement,
                        REGION, ACCOUNT_ID,
                        REGION, ACCOUNT_ID,
                        REGION, ACCOUNT_ID,
                        listenerAddTagsStatement,
                        deleteListenerStatement));
        return new Fixture(allowedName, deniedName, assumeRole(roleName));
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument", trustPolicy())
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when().post("/").then().statusCode(200);
    }

    private static void putRolePolicy(String roleName, String policyDocument) {
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "ScopedElbRuntimeAuthorization")
                .formParam("PolicyDocument", policyDocument)
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when().post("/").then().statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        var response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "elb-runtime-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, "sts"))
        .when().post("/").then().statusCode(200)
                .extract();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static io.restassured.response.ValidatableResponse createTargetGroup(
            SessionCredentials credentials, String name, String managedBy) {
        return createTargetGroup(authenticatedRequest(credentials), name, managedBy);
    }

    private static io.restassured.response.ValidatableResponse createTargetGroup(
            String accessKeyId, String name, String managedBy) {
        return createTargetGroup(authenticatedRequest(accessKeyId), name, managedBy);
    }

    private static io.restassured.response.ValidatableResponse createTargetGroup(
            RequestSpecification request, String name, String managedBy) {
        return request
                .formParam("Action", "CreateTargetGroup")
                .formParam("Name", name)
                .formParam("Protocol", "HTTP")
                .formParam("Port", "8080")
                .formParam("TargetType", "instance")
                .formParam("Tags.member.1.Key", "example.io:definition-id")
                .formParam("Tags.member.1.Value", "example")
                .formParam("Tags.member.2.Key", "example.io:managed-by")
                .formParam("Tags.member.2.Value", managedBy)
        .when().post("/").then();
    }

    private static String createTargetGroupArn(SessionCredentials credentials, String name, String managedBy) {
        return createTargetGroup(credentials, name, managedBy)
                .statusCode(200).extract()
                .path("CreateTargetGroupResponse.CreateTargetGroupResult.TargetGroups.member.TargetGroupArn");
    }

    private static String createTargetGroupArn(String accessKeyId, String name, String managedBy) {
        return createTargetGroup(accessKeyId, name, managedBy)
                .statusCode(200).extract()
                .path("CreateTargetGroupResponse.CreateTargetGroupResult.TargetGroups.member.TargetGroupArn");
    }

    private static io.restassured.response.ValidatableResponse modifyTargetGroupAttributes(
            SessionCredentials credentials, String targetGroupArn) {
        return authenticatedRequest(credentials)
                .formParam("Action", "ModifyTargetGroupAttributes")
                .formParam("TargetGroupArn", targetGroupArn)
                .formParam("Attributes.member.1.Key", "deregistration_delay.timeout_seconds")
                .formParam("Attributes.member.1.Value", "60")
        .when().post("/").then();
    }

    private static io.restassured.response.ValidatableResponse deleteTargetGroup(
            SessionCredentials credentials, String targetGroupArn) {
        return authenticatedRequest(credentials)
                .formParam("Action", "DeleteTargetGroup")
                .formParam("TargetGroupArn", targetGroupArn)
        .when().post("/").then();
    }

    private static io.restassured.response.ValidatableResponse createListener(
            SessionCredentials credentials, String loadBalancerArn, String targetGroupArn, String managedBy) {
        return createListener(authenticatedRequest(credentials), loadBalancerArn, targetGroupArn, managedBy);
    }

    private static io.restassured.response.ValidatableResponse createListener(
            String accessKeyId, String loadBalancerArn, String targetGroupArn, String managedBy) {
        return createListener(authenticatedRequest(accessKeyId), loadBalancerArn, targetGroupArn, managedBy);
    }

    private static io.restassured.response.ValidatableResponse createListener(
            RequestSpecification request, String loadBalancerArn, String targetGroupArn, String managedBy) {
        return request
                .formParam("Action", "CreateListener")
                .formParam("LoadBalancerArn", loadBalancerArn)
                .formParam("Protocol", "HTTP")
                .formParam("Port", "80")
                .formParam("DefaultActions.member.1.Type", "forward")
                .formParam("DefaultActions.member.1.TargetGroupArn", targetGroupArn)
                .formParam("Tags.member.1.Key", "example.io:definition-id")
                .formParam("Tags.member.1.Value", "example")
                .formParam("Tags.member.2.Key", "example.io:managed-by")
                .formParam("Tags.member.2.Value", managedBy)
        .when().post("/").then();
    }

    private static String createListenerArn(
            String loadBalancerName, String targetGroupName, String listenerManagedBy) {
        String loadBalancerArn = createLoadBalancer(loadBalancerName, "floci");
        String targetGroupArn = createTargetGroupArn(ACCOUNT_ID, targetGroupName, "floci");
        return createListener(ACCOUNT_ID, loadBalancerArn, targetGroupArn, listenerManagedBy)
                .statusCode(200).extract()
                .path("CreateListenerResponse.CreateListenerResult.Listeners.member.ListenerArn");
    }

    private static io.restassured.response.ValidatableResponse deleteListener(
            SessionCredentials credentials, String listenerArn) {
        return authenticatedRequest(credentials)
                .formParam("Action", "DeleteListener")
                .formParam("ListenerArn", listenerArn)
        .when().post("/").then();
    }

    private static io.restassured.response.ValidatableResponse describeListener(String listenerArn) {
        return given()
                .formParam("Action", "DescribeListeners")
                .formParam("ListenerArns.member.1", listenerArn)
                .header("Authorization", auth(ACCOUNT_ID, "elasticloadbalancing"))
        .when().post("/").then();
    }

    private static io.restassured.response.ValidatableResponse describeTargetGroup(String targetGroupArn) {
        return given()
                .formParam("Action", "DescribeTargetGroups")
                .formParam("TargetGroupArns.member.1", targetGroupArn)
                .header("Authorization", auth(ACCOUNT_ID, "elasticloadbalancing"))
        .when().post("/").then();
    }

    private static String createLoadBalancer(String name, String managedBy) {
        return given()
                .formParam("Action", "CreateLoadBalancer")
                .formParam("Name", name)
                .formParam("Type", "application")
                .formParam("Scheme", "internal")
                .formParam("Subnets.member.1", "subnet-default-a")
                .formParam("Subnets.member.2", "subnet-default-b")
                .formParam("Tags.member.1.Key", "example.io:definition-id")
                .formParam("Tags.member.1.Value", "example")
                .formParam("Tags.member.2.Key", "example.io:managed-by")
                .formParam("Tags.member.2.Value", managedBy)
                .header("Authorization", auth(ACCOUNT_ID, "elasticloadbalancing"))
        .when().post("/").then().statusCode(200).extract()
                .path("CreateLoadBalancerResponse.CreateLoadBalancerResult.LoadBalancers.member.LoadBalancerArn");
    }

    private static io.restassured.response.ValidatableResponse deleteLoadBalancer(
            SessionCredentials credentials, String loadBalancerArn) {
        return authenticatedRequest(credentials)
                .formParam("Action", "DeleteLoadBalancer")
                .formParam("LoadBalancerArn", loadBalancerArn)
        .when().post("/").then();
    }

    private static io.restassured.response.ValidatableResponse describeLoadBalancer(String loadBalancerArn) {
        return given()
                .formParam("Action", "DescribeLoadBalancers")
                .formParam("LoadBalancerArns.member.1", loadBalancerArn)
                .header("Authorization", auth(ACCOUNT_ID, "elasticloadbalancing"))
        .when().post("/").then();
    }

    private static String trustPolicy() {
        return """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"
                }]}
                """;
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private static RequestSpecification authenticatedRequest(SessionCredentials credentials) {
        return authenticatedRequest(credentials.accessKeyId())
                .header("X-Amz-Security-Token", credentials.sessionToken());
    }

    private static RequestSpecification authenticatedRequest(String accessKeyId) {
        return given().header("Authorization", auth(accessKeyId, "elasticloadbalancing"));
    }

    private record Fixture(String allowedName, String deniedName, SessionCredentials credentials) {}

    private record SessionCredentials(String accessKeyId, String sessionToken) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
