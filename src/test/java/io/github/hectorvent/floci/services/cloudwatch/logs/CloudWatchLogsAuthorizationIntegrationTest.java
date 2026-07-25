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
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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

            assertAccessDenied("logs:CreateLogGroup", assertThrows(CloudWatchLogsException.class,
                    () -> scoped.createLogGroup(request -> request.logGroupName(deniedName))));
            assertAccessDenied("logs:CreateLogGroup", assertThrows(CloudWatchLogsException.class,
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

    @Test
    void tagOperationsAuthorizeTheSuppliedLogGroupArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String allowedName = "/iceguard/" + suffix + "/otel";
        String deniedName = "/other/" + suffix + "/otel";
        String allowedArn = logGroupArn(allowedName);
        String deniedArn = logGroupArn(deniedName);
        RoleCredentials scopedCredentials = roleCredentials(
                "ScopedLogGroupTagger" + suffix,
                List.of(
                        "logs:ListTagsForResource",
                        "logs:TagResource",
                        "logs:UntagResource"),
                allowedArn);
        RoleCredentials missingActionCredentials = roleCredentials(
                "LogGroupDescriber" + suffix,
                "logs:DescribeLogGroups",
                logGroupArn("*"));

        try (CloudWatchLogsClient scoped = logsClient(scopedCredentials);
             CloudWatchLogsClient missingAction = logsClient(missingActionCredentials);
             CloudWatchLogsClient root = logsClient(ACCOUNT_ID)) {
            root.createLogGroup(request -> request.logGroupName(allowedName));
            root.createLogGroup(request -> request.logGroupName(deniedName));

            scoped.tagResource(request -> request
                    .resourceArn(allowedArn)
                    .tags(Map.of("owner", "iceguard")));
            assertEquals(
                    Map.of("owner", "iceguard"),
                    scoped.listTagsForResource(request -> request.resourceArn(allowedArn)).tags());
            scoped.untagResource(request -> request
                    .resourceArn(allowedArn)
                    .tagKeys("owner"));
            assertEquals(
                    Map.of(),
                    scoped.listTagsForResource(request -> request.resourceArn(allowedArn)).tags());

            assertAccessDenied("logs:ListTagsForResource", assertThrows(CloudWatchLogsException.class,
                    () -> scoped.listTagsForResource(request -> request.resourceArn(deniedArn))));
            assertAccessDenied("logs:TagResource", assertThrows(CloudWatchLogsException.class,
                    () -> scoped.tagResource(request -> request
                            .resourceArn(deniedArn)
                            .tags(Map.of("owner", "other")))));
            assertAccessDenied("logs:ListTagsForResource", assertThrows(CloudWatchLogsException.class,
                    () -> missingAction.listTagsForResource(request -> request.resourceArn(allowedArn))));

            assertEquals(
                    Map.of(),
                    root.listTagsForResource(request -> request.resourceArn(deniedArn)).tags());
            root.deleteLogGroup(request -> request.logGroupName(allowedName));
            root.deleteLogGroup(request -> request.logGroupName(deniedName));
        }
    }

    @Test
    void groupLifecycleOperationsAuthorizeTheRequestedLogGroupArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String allowedName = "/iceguard/" + suffix + "/otel";
        String deniedName = "/other/" + suffix + "/otel";
        RoleCredentials scopedCredentials = roleCredentials(
                "ScopedLogGroupLifecycle" + suffix,
                List.of("logs:PutRetentionPolicy", "logs:DeleteLogGroup"),
                logGroupArn(allowedName));
        RoleCredentials missingActionCredentials = roleCredentials(
                "LogGroupLifecycleReader" + suffix,
                "logs:DescribeLogGroups",
                logGroupArn("*"));

        try (CloudWatchLogsClient scoped = logsClient(scopedCredentials);
             CloudWatchLogsClient missingAction = logsClient(missingActionCredentials);
             CloudWatchLogsClient root = logsClient(ACCOUNT_ID)) {
            root.createLogGroup(request -> request.logGroupName(allowedName));
            root.createLogGroup(request -> request.logGroupName(deniedName));

            scoped.putRetentionPolicy(request -> request
                    .logGroupName(allowedName)
                    .retentionInDays(14));
            assertEquals(
                    14,
                    root.describeLogGroups(request -> request.logGroupNamePrefix(allowedName))
                            .logGroups()
                            .getFirst()
                            .retentionInDays());

            assertAccessDenied("logs:PutRetentionPolicy", assertThrows(CloudWatchLogsException.class,
                    () -> scoped.putRetentionPolicy(request -> request
                            .logGroupName(deniedName)
                            .retentionInDays(30))));
            assertAccessDenied("logs:PutRetentionPolicy", assertThrows(CloudWatchLogsException.class,
                    () -> missingAction.putRetentionPolicy(request -> request
                            .logGroupName(allowedName)
                            .retentionInDays(30))));
            assertNull(root.describeLogGroups(request -> request.logGroupNamePrefix(deniedName))
                    .logGroups()
                    .getFirst()
                    .retentionInDays());

            scoped.deleteLogGroup(request -> request.logGroupName(allowedName));
            assertTrue(root.describeLogGroups(request -> request.logGroupNamePrefix(allowedName))
                    .logGroups()
                    .isEmpty());
            assertAccessDenied("logs:DeleteLogGroup", assertThrows(CloudWatchLogsException.class,
                    () -> scoped.deleteLogGroup(request -> request.logGroupName(deniedName))));
            root.deleteLogGroup(request -> request.logGroupName(deniedName));
        }
    }

    @Test
    void streamLifecycleOperationsAuthorizeTheRequestedLogStreamArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String allowedName = "/iceguard/" + suffix + "/otel";
        String deniedName = "/other/" + suffix + "/otel";
        String streamName = "application";
        RoleCredentials scopedCredentials = roleCredentials(
                "ScopedLogStreamLifecycle" + suffix,
                List.of("logs:CreateLogStream", "logs:DeleteLogStream"),
                logGroupArn(allowedName) + ":log-stream:*");
        RoleCredentials missingActionCredentials = roleCredentials(
                "LogStreamLifecycleReader" + suffix,
                "logs:DescribeLogStreams",
                logGroupArn("*") + ":log-stream:*");

        try (CloudWatchLogsClient scoped = logsClient(scopedCredentials);
             CloudWatchLogsClient missingAction = logsClient(missingActionCredentials);
             CloudWatchLogsClient root = logsClient(ACCOUNT_ID)) {
            root.createLogGroup(request -> request.logGroupName(allowedName));
            root.createLogGroup(request -> request.logGroupName(deniedName));
            root.createLogStream(request -> request
                    .logGroupName(deniedName)
                    .logStreamName(streamName));

            scoped.createLogStream(request -> request
                    .logGroupName(allowedName)
                    .logStreamName(streamName));
            assertEquals(
                    List.of(streamName),
                    root.describeLogStreams(request -> request.logGroupName(allowedName))
                            .logStreams()
                            .stream()
                            .map(stream -> stream.logStreamName())
                            .toList());

            assertAccessDenied("logs:CreateLogStream", assertThrows(CloudWatchLogsException.class,
                    () -> scoped.createLogStream(request -> request
                            .logGroupName(deniedName)
                            .logStreamName("denied"))));
            assertAccessDenied("logs:CreateLogStream", assertThrows(CloudWatchLogsException.class,
                    () -> missingAction.createLogStream(request -> request
                            .logGroupName(allowedName)
                            .logStreamName("missing-action"))));

            scoped.deleteLogStream(request -> request
                    .logGroupName(allowedName)
                    .logStreamName(streamName));
            assertTrue(root.describeLogStreams(request -> request.logGroupName(allowedName))
                    .logStreams()
                    .isEmpty());
            assertAccessDenied("logs:DeleteLogStream", assertThrows(CloudWatchLogsException.class,
                    () -> scoped.deleteLogStream(request -> request
                            .logGroupName(deniedName)
                            .logStreamName(streamName))));
            assertEquals(
                    List.of(streamName),
                    root.describeLogStreams(request -> request.logGroupName(deniedName))
                            .logStreams()
                            .stream()
                            .map(stream -> stream.logStreamName())
                            .toList());

            root.deleteLogGroup(request -> request.logGroupName(allowedName));
            root.deleteLogGroup(request -> request.logGroupName(deniedName));
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
        return roleCredentials(roleName, List.of(action), resource);
    }

    private static RoleCredentials roleCredentials(String roleName, List<String> actions, String resource) {
        createRole(roleName);
        putRolePolicy(roleName, actions, resource);
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

    private static void putRolePolicy(String roleName, List<String> actions, String resource) {
        String actionJson = actions.size() == 1
                ? "\"%s\"".formatted(actions.getFirst())
                : actions.stream()
                        .map(action -> "\"%s\"".formatted(action))
                        .collect(java.util.stream.Collectors.joining(",", "[", "]"));
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "ScopedLogs")
                .formParam("PolicyDocument", """
                        {
                          "Version": "2012-10-17",
                          "Statement": [{
                            "Effect": "Allow",
                            "Action": %s,
                            "Resource": "%s"
                          }]
                        }
                        """.formatted(actionJson, resource))
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

    private static void assertAccessDenied(String action, CloudWatchLogsException exception) {
        assertEquals(403, exception.statusCode());
        assertEquals("AccessDeniedException", exception.awsErrorDetails().errorCode());
        assertTrue(exception.getMessage().contains(action));
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
