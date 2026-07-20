package io.github.hectorvent.floci.services.elbv2;

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
@TestProfile(ElbV2CreateLoadBalancerAuthorizationIntegrationTest.IamEnforcementProfile.class)
class ElbV2CreateLoadBalancerAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";

    @Test
    void authorizesTheFutureApplicationLoadBalancerArnAndRequestTags() {
        Fixture fixture = createFixture();

        createLoadBalancer(fixture.credentials(), fixture.allowedName(), "floci")
                .statusCode(200)
                .body("CreateLoadBalancerResponse.CreateLoadBalancerResult.LoadBalancers.member.LoadBalancerArn",
                        startsWith("arn:aws:elasticloadbalancing:" + REGION + ":" + ACCOUNT_ID
                                + ":loadbalancer/app/" + fixture.allowedName() + "/"));
    }

    @Test
    void rejectsALoadBalancerOutsideTheAuthorizedNameScope() {
        Fixture fixture = createFixture();

        createLoadBalancer(fixture.credentials(), fixture.deniedName(), "floci")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:CreateLoadBalancer"));
    }

    @Test
    void rejectsMismatchedCreateRequestTags() {
        Fixture fixture = createFixture();

        createLoadBalancer(fixture.credentials(), fixture.allowedName(), "other")
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"))
                .body(containsString("elasticloadbalancing:CreateLoadBalancer"));
    }

    private static Fixture createFixture() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String roleName = "LoadBalancerCreator" + suffix;
        String allowedName = "team-a-" + suffix;
        String deniedName = "team-b-" + suffix;
        createRole(roleName);
        putRolePolicy(roleName, """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "elasticloadbalancing:CreateLoadBalancer",
                    "Resource": "arn:aws:elasticloadbalancing:%s:%s:loadbalancer/app/team-a-*",
                    "Condition": {
                      "StringEquals": {
                        "aws:RequestTag/example.io:definition-id": "example",
                        "aws:RequestTag/example.io:managed-by": "floci"
                      }
                    }
                  }]
                }
                """.formatted(REGION, ACCOUNT_ID));
        return new Fixture(allowedName, deniedName, assumeRole(roleName));
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument", trustPolicy())
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
                .formParam("PolicyName", "ScopedLoadBalancerCreation")
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
                .formParam("RoleSessionName", "load-balancer-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, "sts"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static io.restassured.response.ValidatableResponse createLoadBalancer(
            SessionCredentials credentials, String name, String managedBy) {
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
                .header("Authorization", auth(credentials.accessKeyId(), "elasticloadbalancing"))
                .header("X-Amz-Security-Token", credentials.sessionToken())
        .when()
                .post("/")
        .then();
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

    private record Fixture(String allowedName, String deniedName, SessionCredentials credentials) {}

    private record SessionCredentials(String accessKeyId, String sessionToken) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
