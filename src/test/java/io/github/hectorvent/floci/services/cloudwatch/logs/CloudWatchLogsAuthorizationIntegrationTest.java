package io.github.hectorvent.floci.services.cloudwatch.logs;

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
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.CloudWatchLogsException;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(CloudWatchLogsAuthorizationIntegrationTest.IamEnforcementProfile.class)
class CloudWatchLogsAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";

    @Test
    void createLogGroupAuthorizesTheRequestedAwsArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String allowedName = "/iceguard/" + suffix + "/otel";
        String deniedName = "/other/" + suffix + "/otel";
        RoleCredentials scopedCredentials = roleCredentials(
                "ScopedLogGroupCreator" + suffix,
                "logs:CreateLogGroup",
                logGroupArn("/iceguard/*/otel"));
        RoleCredentials missingActionCredentials = roleCredentials(
                "LogGroupReader" + suffix,
                "logs:DescribeLogGroups",
                logGroupArn("*"));

        try (CloudWatchLogsClient scoped = logsClient(scopedCredentials);
             CloudWatchLogsClient missingAction = logsClient(missingActionCredentials);
             CloudWatchLogsClient root = logsClient(ACCOUNT_ID)) {
            scoped.createLogGroup(request -> request.logGroupName(allowedName));
            assertTrue(root.describeLogGroups(request -> request.logGroupNamePrefix(allowedName))
                    .logGroups()
                    .stream()
                    .anyMatch(group -> allowedName.equals(group.logGroupName())));

            assertAccessDenied(assertThrows(CloudWatchLogsException.class,
                    () -> scoped.createLogGroup(request -> request.logGroupName(deniedName))));
            assertAccessDenied(assertThrows(CloudWatchLogsException.class,
                    () -> missingAction.createLogGroup(request -> request.logGroupName(allowedName + "-other"))));

            assertTrue(root.describeLogGroups(request -> request.logGroupNamePrefix(deniedName))
                    .logGroups()
                    .isEmpty());
            assertTrue(root.describeLogGroups(request -> request.logGroupNamePrefix(allowedName + "-other"))
                    .logGroups()
                    .isEmpty());
            root.deleteLogGroup(request -> request.logGroupName(allowedName));
        }
    }

    private static CloudWatchLogsClient logsClient(String accessKeyId) {
        return CloudWatchLogsClient.builder()
                .endpointOverride(URI.create("http://localhost:" + RestAssured.port))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKeyId, "test-secret-key")))
                .build();
    }

    private static CloudWatchLogsClient logsClient(RoleCredentials credentials) {
        return CloudWatchLogsClient.builder()
                .endpointOverride(URI.create("http://localhost:" + RestAssured.port))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsSessionCredentials.create(
                                credentials.accessKeyId(),
                                credentials.secretAccessKey(),
                                credentials.sessionToken())))
                .build();
    }

    private static RoleCredentials roleCredentials(String roleName, String action, String resource) {
        createRole(roleName);
        putRolePolicy(roleName, action, resource);
        return assumeRole(roleName);
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
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

    private static void putRolePolicy(String roleName, String action, String resource) {
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "ScopedLogs")
                .formParam("PolicyDocument", """
                        {
                          "Version": "2012-10-17",
                          "Statement": [{
                            "Effect": "Allow",
                            "Action": "%s",
                            "Resource": "%s"
                          }]
                        }
                        """.formatted(action, resource))
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static RoleCredentials assumeRole(String roleName) {
        var credentials = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "logs-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, "sts"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract()
                .xmlPath();
        return new RoleCredentials(
                credentials.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                credentials.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.SecretAccessKey"),
                credentials.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static String logGroupArn(String name) {
        return "arn:aws:logs:" + REGION + ":" + ACCOUNT_ID + ":log-group:" + name;
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260725/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private static void assertAccessDenied(CloudWatchLogsException exception) {
        assertEquals(403, exception.statusCode());
        assertEquals("AccessDeniedException", exception.awsErrorDetails().errorCode());
        assertTrue(exception.getMessage().contains("logs:CreateLogGroup"));
    }

    private record RoleCredentials(String accessKeyId, String secretAccessKey, String sessionToken) {
    }

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
