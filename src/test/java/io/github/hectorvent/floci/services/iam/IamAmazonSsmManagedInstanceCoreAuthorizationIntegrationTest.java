package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;
import software.amazon.awssdk.services.ssm.SsmClient;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(IamAmazonSsmManagedInstanceCoreAuthorizationIntegrationTest.IamEnforcementProfile.class)
class IamAmazonSsmManagedInstanceCoreAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";
    private static final String SSM_POLICY_ARN =
            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore";

    @BeforeAll
    static void configureAwsJsonProtocol() {
        io.github.hectorvent.floci.testing.RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void limitsAmazonSsmManagedInstanceCoreToItsPublishedPermissions() {
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String roleName = "SsmManagedInstance" + suffix;
        String allowedSecretName = "application/allowed-" + suffix;
        String siblingSecretName = "application/sibling-" + suffix;
        String parameterName = "/application/config-" + suffix;

        try (IamClient iam = iamClient(rootCredentials());
                SecretsManagerClient rootSecrets = secretsClient(rootCredentials());
                SsmClient rootSsm = ssmClient(rootCredentials())) {
            String allowedSecretArn = rootSecrets.createSecret(request -> request
                            .name(allowedSecretName)
                            .secretString("original-value"))
                    .arn();
            rootSecrets.createSecret(request -> request
                    .name(siblingSecretName)
                    .secretString("sibling-value"));
            rootSsm.putParameter(request -> request
                    .name(parameterName)
                    .value("parameter-value")
                    .type("String"));

            iam.createRole(request -> request
                    .roleName(roleName)
                    .assumeRolePolicyDocument(trustPolicy()));
            iam.putRolePolicy(request -> request
                    .roleName(roleName)
                    .policyName("ApplicationSecretRead")
                    .policyDocument(secretReadPolicy(allowedSecretArn)));
            iam.attachRolePolicy(request -> request
                    .roleName(roleName)
                    .policyArn(SSM_POLICY_ARN));

            AwsCredentialsProvider roleCredentials = assumeRole(roleName);
            try (SecretsManagerClient roleSecrets = secretsClient(roleCredentials);
                    SsmClient roleSsm = ssmClient(roleCredentials)) {
                assertEquals("parameter-value", roleSsm.getParameter(request -> request
                                .name(parameterName))
                        .parameter().value());
                assertEquals(1, roleSsm.getParameters(request -> request
                                .names(parameterName))
                        .parameters().size());
                assertTrue(roleSsm.listAssociations().associations().isEmpty());
                assertEquals("original-value", roleSecrets.getSecretValue(request -> request
                                .secretId(allowedSecretName))
                        .secretString());

                SecretsManagerException putDenied = null;
                try {
                    roleSecrets.putSecretValue(request -> request
                            .secretId(allowedSecretName)
                            .secretString("unauthorized-value"));
                } catch (SecretsManagerException e) {
                    putDenied = e;
                }

                String storedValue = rootSecrets.getSecretValue(request -> request
                                .secretId(allowedSecretName))
                        .secretString();
                int versionCount = rootSecrets.listSecretVersionIds(request -> request
                                .secretId(allowedSecretName))
                        .versions().size();
                assertNotNull(putDenied,
                        "AmazonSSMManagedInstanceCore incorrectly authorized PutSecretValue; stored value="
                                + storedValue + ", versions=" + versionCount);
                assertAccessDenied(putDenied, "secretsmanager:PutSecretValue");
                assertEquals("original-value", storedValue);
                assertEquals(1, versionCount);

                SecretsManagerException siblingDenied = assertThrows(SecretsManagerException.class,
                        () -> roleSecrets.getSecretValue(request -> request.secretId(siblingSecretName)));
                assertAccessDenied(siblingDenied, "secretsmanager:GetSecretValue");
            }
        }
    }

    private static IamClient iamClient(AwsCredentialsProvider credentials) {
        return IamClient.builder()
                .endpointOverride(endpoint())
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(credentials)
                .build();
    }

    private static SecretsManagerClient secretsClient(AwsCredentialsProvider credentials) {
        return SecretsManagerClient.builder()
                .endpointOverride(endpoint())
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(credentials)
                .build();
    }

    private static SsmClient ssmClient(AwsCredentialsProvider credentials) {
        return SsmClient.builder()
                .endpointOverride(endpoint())
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(credentials)
                .build();
    }

    private static AwsCredentialsProvider rootCredentials() {
        return StaticCredentialsProvider.create(
                AwsBasicCredentials.create(ACCOUNT_ID, "test-secret-key"));
    }

    private static AwsCredentialsProvider assumeRole(String roleName) {
        var response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "ssm-managed-instance-core-test")
                .header("Authorization", auth(ACCOUNT_ID, "sts"))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract()
                .xmlPath();
        return StaticCredentialsProvider.create(AwsSessionCredentials.create(
                response.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.SecretAccessKey"),
                response.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken")));
    }

    private static URI endpoint() {
        return URI.create("http://localhost:" + RestAssured.port);
    }

    private static String trustPolicy() {
        return """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sts:AssumeRole"
                  }]
                }
                """;
    }

    private static String secretReadPolicy(String secretArn) {
        return """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                      "secretsmanager:DescribeSecret",
                      "secretsmanager:GetSecretValue"
                    ],
                    "Resource": "%s"
                  }]
                }
                """.formatted(secretArn);
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260721/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private static void assertAccessDenied(SecretsManagerException exception, String action) {
        assertEquals(403, exception.statusCode());
        assertEquals("AccessDeniedException", exception.awsErrorDetails().errorCode());
        assertTrue(exception.getMessage().contains(action));
        assertNotNull(exception.requestId());
    }

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
