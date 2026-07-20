package com.floci.test;

import org.junit.jupiter.api.*;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.CreateRoleRequest;
import software.amazon.awssdk.services.iam.model.DeleteRoleRequest;
import software.amazon.awssdk.services.iam.model.GetRoleRequest;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.*;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

@DisplayName("STS Security Token Service")
class StsTest {

    private static StsClient sts;
    private static IamClient iam;
    private static final List<String> ROLE_NAMES = List.of(
            "sdk-test-assumed-role",
            "my-role",
            "sdk-issued-role",
            "short-lived-role",
            "web-identity-role",
            "saml-role",
            "my-saml-role");
    private static final String TRUST_POLICY = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}
            ]}
            """;

    @BeforeAll
    static void setup() {
        sts = TestFixtures.stsClient();
        iam = TestFixtures.iamClient();
        for (String roleName : ROLE_NAMES) {
            try {
                iam.getRole(GetRoleRequest.builder().roleName(roleName).build());
            } catch (NoSuchEntityException e) {
                iam.createRole(CreateRoleRequest.builder()
                        .roleName(roleName)
                        .assumeRolePolicyDocument(TRUST_POLICY)
                        .build());
            }
        }
    }

    @AfterAll
    static void cleanup() {
        if (iam != null) {
            for (String roleName : ROLE_NAMES) {
                try {
                    iam.deleteRole(DeleteRoleRequest.builder().roleName(roleName).build());
                } catch (Exception e) {
                    System.err.println("Unable to delete STS SDK fixture role " + roleName
                            + ": " + e.getMessage());
                }
            }
            iam.close();
        }
        if (sts != null) {
            sts.close();
        }
    }

    @Test
    void getCallerIdentity() {
        GetCallerIdentityResponse response = sts.getCallerIdentity(
                GetCallerIdentityRequest.builder().build());

        assertThat(response.account()).isNotNull();
        assertThat(response.arn()).isNotNull();
        assertThat(response.userId()).isNotNull();
    }

    @Test
    void getCallerIdentityAccountId() {
        GetCallerIdentityResponse response = sts.getCallerIdentity(
                GetCallerIdentityRequest.builder().build());

        assertThat(response.account()).isEqualTo("000000000000");
    }

    @Test
    void assumeRole() {
        AssumeRoleResponse response = sts.assumeRole(AssumeRoleRequest.builder()
                .roleArn("arn:aws:iam::000000000000:role/sdk-test-assumed-role")
                .roleSessionName("sdk-test-session")
                .durationSeconds(3600)
                .build());

        assertThat(response.credentials()).isNotNull();
        assertThat(response.credentials().accessKeyId()).startsWith("ASIA");
        assertThat(response.credentials().secretAccessKey()).isNotNull();
        assertThat(response.credentials().sessionToken()).isNotNull();
        assertThat(response.credentials().expiration()).isNotNull();
    }

    @Test
    void assumeRoleReturnsAssumedRoleUserArn() {
        AssumeRoleResponse response = sts.assumeRole(AssumeRoleRequest.builder()
                .roleArn("arn:aws:iam::000000000000:role/my-role")
                .roleSessionName("my-session")
                .build());

        assertThat(response.assumedRoleUser()).isNotNull();
        assertThat(response.assumedRoleUser().arn()).contains("assumed-role/my-role/my-session");
    }

    @Test
    void issuedSessionCredentialsReturnExactCallerIdentity() {
        String accountId = "000000000000";
        String sessionName = "sdk-issued-session";
        AssumeRoleResponse assumed = sts.assumeRole(AssumeRoleRequest.builder()
                .roleArn("arn:aws:iam::" + accountId + ":role/sdk-issued-role")
                .roleSessionName(sessionName)
                .build());
        Credentials credentials = assumed.credentials();

        try (StsClient sessionSts = StsClient.builder()
                .endpointOverride(TestFixtures.endpoint())
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsSessionCredentials.create(
                        credentials.accessKeyId(), credentials.secretAccessKey(), credentials.sessionToken())))
                .build()) {
            GetCallerIdentityResponse identity = sessionSts.getCallerIdentity();

            assertThat(identity.account()).isEqualTo(accountId);
            assertThat(identity.arn()).isEqualTo("arn:aws:sts::" + accountId
                    + ":assumed-role/sdk-issued-role/" + sessionName);
            assertThat(identity.userId()).isEqualTo(assumed.assumedRoleUser().assumedRoleId());
        }
    }

    @Test
    void assumeRoleWithCustomDuration() {
        AssumeRoleResponse response = sts.assumeRole(AssumeRoleRequest.builder()
                .roleArn("arn:aws:iam::000000000000:role/short-lived-role")
                .roleSessionName("short-session")
                .durationSeconds(900)
                .build());

        assertThat(response.credentials()).isNotNull();
        assertThat(response.credentials().expiration()).isBefore(Instant.now().plusSeconds(901));
    }

    @Test
    void getSessionToken() {
        GetSessionTokenResponse response = sts.getSessionToken(
                GetSessionTokenRequest.builder().durationSeconds(7200).build());

        assertThat(response.credentials()).isNotNull();
        assertThat(response.credentials().accessKeyId()).startsWith("ASIA");
        assertThat(response.credentials().sessionToken()).isNotNull();
        assertThat(response.credentials().expiration()).isAfter(Instant.now());
    }

    @Test
    void getSessionTokenCredentialsCannotRequestAnotherSessionToken() {
        Credentials credentials = sts.getSessionToken().credentials();

        try (StsClient sessionSts = StsClient.builder()
                .endpointOverride(TestFixtures.endpoint())
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsSessionCredentials.create(
                        credentials.accessKeyId(), credentials.secretAccessKey(), credentials.sessionToken())))
                .build()) {
            assertThatThrownBy(sessionSts::getSessionToken)
                    .isInstanceOf(StsException.class)
                    .satisfies(error -> {
                        StsException stsError = (StsException) error;
                        assertThat(stsError.statusCode()).isEqualTo(403);
                        assertThat(stsError.awsErrorDetails().errorCode()).isEqualTo("AccessDenied");
                    });
        }
    }

    @Test
    void assumeRoleWithWebIdentity() {
        AssumeRoleWithWebIdentityResponse response = sts.assumeRoleWithWebIdentity(
                AssumeRoleWithWebIdentityRequest.builder()
                        .roleArn("arn:aws:iam::000000000000:role/web-identity-role")
                        .roleSessionName("web-session")
                        .webIdentityToken("eyJhbGciOiJSUzI1NiJ9.test-token")
                        .durationSeconds(3600)
                        .build());

        assertThat(response.credentials()).isNotNull();
        assertThat(response.credentials().accessKeyId()).startsWith("ASIA");
        assertThat(response.assumedRoleUser().arn()).contains("assumed-role/web-identity-role/web-session");
    }

    @Test
    void getFederationToken() {
        GetFederationTokenResponse response = sts.getFederationToken(
                GetFederationTokenRequest.builder()
                        .name("sdk-test-feduser")
                        .durationSeconds(3600)
                        .build());

        assertThat(response.credentials()).isNotNull();
        assertThat(response.credentials().accessKeyId()).startsWith("ASIA");
        assertThat(response.federatedUser().arn()).contains("federated-user/sdk-test-feduser");
    }

    @Test
    void decodeAuthorizationMessage() {
        DecodeAuthorizationMessageResponse response = sts.decodeAuthorizationMessage(
                DecodeAuthorizationMessageRequest.builder()
                        .encodedMessage("test-encoded-message")
                        .build());

        assertThat(response.decodedMessage()).isNotEmpty();
    }

    @Test
    void assumeRoleMissingRoleArnThrows400() {
        assertThatThrownBy(() -> sts.assumeRole(AssumeRoleRequest.builder()
                .roleSessionName("s")
                .build()))
                .isInstanceOf(StsException.class)
                .extracting(e -> ((StsException) e).statusCode())
                .isEqualTo(400);
    }

    @Test
    void assumeRoleRejectsUnknownRole() {
        assertThatThrownBy(() -> sts.assumeRole(AssumeRoleRequest.builder()
                .roleArn("arn:aws:iam::000000000000:role/sdk-test-missing-role")
                .roleSessionName("missing-session")
                .build()))
                .isInstanceOf(StsException.class)
                .satisfies(error -> {
                    StsException stsError = (StsException) error;
                    assertThat(stsError.statusCode()).isEqualTo(403);
                    assertThat(stsError.awsErrorDetails().errorCode()).isEqualTo("AccessDenied");
                });
    }

    @Test
    void assumeRoleWithSaml() {
        AssumeRoleWithSamlResponse response = sts.assumeRoleWithSAML(
                AssumeRoleWithSamlRequest.builder()
                        .roleArn("arn:aws:iam::000000000000:role/saml-role")
                        .principalArn("arn:aws:iam::000000000000:saml-provider/MySAML")
                        .samlAssertion("base64-encoded-saml-assertion")
                        .durationSeconds(3600)
                        .build());

        assertThat(response.credentials()).isNotNull();
        assertThat(response.credentials().accessKeyId()).startsWith("ASIA");
        assertThat(response.credentials().secretAccessKey()).isNotNull();
        assertThat(response.credentials().sessionToken()).isNotNull();
        assertThat(response.credentials().expiration()).isAfter(Instant.now());
    }

    @Test
    void assumeRoleWithSamlAssumedRoleUser() {
        AssumeRoleWithSamlResponse response = sts.assumeRoleWithSAML(
                AssumeRoleWithSamlRequest.builder()
                        .roleArn("arn:aws:iam::000000000000:role/my-saml-role")
                        .principalArn("arn:aws:iam::000000000000:saml-provider/Corp")
                        .samlAssertion("assertion")
                        .build());

        assertThat(response.assumedRoleUser()).isNotNull();
        assertThat(response.assumedRoleUser().arn()).contains("assumed-role/my-saml-role/");
    }

    @Test
    void assumeRoleWithWebIdentityMissingTokenThrows400() {
        assertThatThrownBy(() -> sts.assumeRoleWithWebIdentity(
                AssumeRoleWithWebIdentityRequest.builder()
                        .roleArn("arn:aws:iam::000000000000:role/r")
                        .roleSessionName("s")
                        .build()))
                .isInstanceOf(StsException.class)
                .extracting(e -> ((StsException) e).statusCode())
                .isEqualTo(400);
    }

    @Test
    void getFederationTokenFederatedUserIdFormat() {
        GetFederationTokenResponse response = sts.getFederationToken(
                GetFederationTokenRequest.builder()
                        .name("myuser")
                        .build());

        assertThat(response.federatedUser()).isNotNull();
        assertThat(response.federatedUser().federatedUserId()).isEqualTo("000000000000:myuser");
    }

    @Test
    void getFederationTokenMissingNameThrows400() {
        assertThatThrownBy(() -> sts.getFederationToken(
                GetFederationTokenRequest.builder().build()))
                .isInstanceOf(StsException.class)
                .extracting(e -> ((StsException) e).statusCode())
                .isEqualTo(400);
    }

    @Test
    void getSessionTokenDefaultDuration() {
        GetSessionTokenResponse response = sts.getSessionToken(
                GetSessionTokenRequest.builder().build());

        assertThat(response.credentials()).isNotNull();
        assertThat(response.credentials().expiration()).isAfter(Instant.now().plusSeconds(3600));
    }

    @Test
    void decodeAuthorizationMessageEcho() {
        String msg = "exact-message-to-echo-back";
        DecodeAuthorizationMessageResponse response = sts.decodeAuthorizationMessage(
                DecodeAuthorizationMessageRequest.builder()
                        .encodedMessage(msg)
                        .build());

        assertThat(response.decodedMessage()).isEqualTo(msg);
    }

    @Test
    void decodeAuthorizationMessageMissingMessageThrows400() {
        assertThatThrownBy(() -> sts.decodeAuthorizationMessage(
                DecodeAuthorizationMessageRequest.builder().build()))
                .isInstanceOf(StsException.class)
                .extracting(e -> ((StsException) e).statusCode())
                .isEqualTo(400);
    }
}
