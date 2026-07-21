package com.floci.test;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.CreateInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.CreateRoleRequest;
import software.amazon.awssdk.services.iam.model.DeleteInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.DeleteRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.DeleteRoleRequest;
import software.amazon.awssdk.services.iam.model.GetInstanceProfileRequest;
import software.amazon.awssdk.services.iam.model.GetRoleRequest;
import software.amazon.awssdk.services.iam.model.IamException;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;
import software.amazon.awssdk.services.iam.model.PutRolePolicyRequest;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.util.List;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IamDeleteInstanceProfileAuthorizationTest {

    private static final Logger LOG = Logger.getLogger(
            IamDeleteInstanceProfileAuthorizationTest.class.getName());
    private static final String TRUST_POLICY = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"
            }]}
            """;

    @Test
    void assumedSessionRequiresExactExistingProfileToDeleteInstanceProfile() {
        String suffix = TestFixtures.uniqueName("delete-instance-profile");
        String callerRole = suffix + "-operator";
        String noPermissionRole = suffix + "-observer";
        String allowedProfile = suffix + "-allowed-profile";
        String deniedProfile = suffix + "-denied-profile";
        String missingPermissionProfile = suffix + "-missing-permission-profile";
        String path = "/provisioned/";

        try (IamClient root = TestFixtures.iamClient(); StsClient sts = TestFixtures.stsClient()) {
            String callerRoleArn = createRole(root, callerRole);
            createRole(root, noPermissionRole);
            String allowedProfileArn = createProfile(root, allowedProfile, path);
            createProfile(root, deniedProfile, path);
            createProfile(root, missingPermissionProfile, path);
            root.putRolePolicy(PutRolePolicyRequest.builder()
                    .roleName(callerRole)
                    .policyName("ScopedInstanceProfileDeletion")
                    .policyDocument("""
                            {
                              "Version": "2012-10-17",
                              "Statement": [{
                                "Effect": "Allow",
                                "Action": "iam:DeleteInstanceProfile",
                                "Resource": "%s"
                              }]
                            }
                            """.formatted(allowedProfileArn))
                    .build());

            Credentials caller = assumeRole(sts, callerRoleArn, "delete-instance-profile-authorized");
            Credentials observer = assumeRole(
                    sts, roleArn(noPermissionRole), "delete-instance-profile-observer");
            try (IamClient client = sessionClient(caller);
                    IamClient noPermissionClient = sessionClient(observer)) {
                Assumptions.assumeTrue(enforcementEnabled(noPermissionClient, callerRole),
                        "IAM enforcement is disabled");

                client.deleteInstanceProfile(request -> request.instanceProfileName(allowedProfile));
                assertProfileAbsent(root, allowedProfile);

                assertAccessDenied(() -> client.deleteInstanceProfile(request -> request
                        .instanceProfileName(deniedProfile)));
                assertProfilePresent(root, deniedProfile, path);

                assertAccessDenied(() -> noPermissionClient.deleteInstanceProfile(request -> request
                        .instanceProfileName(missingPermissionProfile)));
                assertProfilePresent(root, missingPermissionProfile, path);
            } finally {
                cleanup(root, callerRole, noPermissionRole,
                        allowedProfile, deniedProfile, missingPermissionProfile);
            }
        }
    }

    private static String createRole(IamClient iam, String roleName) {
        return iam.createRole(CreateRoleRequest.builder()
                        .roleName(roleName)
                        .assumeRolePolicyDocument(TRUST_POLICY)
                        .build())
                .role().arn();
    }

    private static String createProfile(IamClient iam, String profileName, String path) {
        return iam.createInstanceProfile(CreateInstanceProfileRequest.builder()
                        .instanceProfileName(profileName)
                        .path(path)
                        .build())
                .instanceProfile().arn();
    }

    private static Credentials assumeRole(StsClient sts, String roleArn, String sessionName) {
        return sts.assumeRole(AssumeRoleRequest.builder()
                        .roleArn(roleArn)
                        .roleSessionName(sessionName)
                        .build())
                .credentials();
    }

    private static IamClient sessionClient(Credentials credentials) {
        return IamClient.builder()
                .endpointOverride(TestFixtures.endpoint())
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsSessionCredentials.create(
                                credentials.accessKeyId(),
                                credentials.secretAccessKey(),
                                credentials.sessionToken())))
                .build();
    }

    private static boolean enforcementEnabled(IamClient iam, String roleName) {
        try {
            iam.getRole(GetRoleRequest.builder().roleName(roleName).build());
            return false;
        } catch (IamException e) {
            return e.statusCode() == 403 && "AccessDenied".equals(e.awsErrorDetails().errorCode());
        }
    }

    private static void assertAccessDenied(Runnable request) {
        assertThatThrownBy(request::run)
                .isInstanceOf(IamException.class)
                .satisfies(error -> {
                    IamException iamError = (IamException) error;
                    assertThat(iamError.statusCode()).isEqualTo(403);
                    assertThat(iamError.awsErrorDetails().errorCode()).isEqualTo("AccessDenied");
                    assertThat(iamError.requestId()).isNotBlank();
                });
    }

    private static void assertProfileAbsent(IamClient iam, String profileName) {
        assertThatThrownBy(() -> iam.getInstanceProfile(GetInstanceProfileRequest.builder()
                        .instanceProfileName(profileName)
                        .build()))
                .isInstanceOf(NoSuchEntityException.class)
                .satisfies(error -> assertThat(((NoSuchEntityException) error).statusCode())
                        .isEqualTo(404));
    }

    private static void assertProfilePresent(IamClient iam, String profileName, String path) {
        var profile = iam.getInstanceProfile(GetInstanceProfileRequest.builder()
                        .instanceProfileName(profileName)
                        .build())
                .instanceProfile();
        assertThat(profile.instanceProfileName()).isEqualTo(profileName);
        assertThat(profile.path()).isEqualTo(path);
        assertThat(profile.arn()).isEqualTo(instanceProfileArn(path, profileName));
    }

    private static void cleanup(
            IamClient iam,
            String callerRole,
            String observerRole,
            String allowedProfile,
            String deniedProfile,
            String missingPermissionProfile) {
        for (String profile : List.of(allowedProfile, deniedProfile, missingPermissionProfile)) {
            cleanup("delete instance profile " + profile,
                    () -> iam.deleteInstanceProfile(DeleteInstanceProfileRequest.builder()
                            .instanceProfileName(profile)
                            .build()));
        }
        cleanup("delete scoped deletion policy", () -> iam.deleteRolePolicy(
                DeleteRolePolicyRequest.builder()
                        .roleName(callerRole)
                        .policyName("ScopedInstanceProfileDeletion")
                        .build()));
        for (String role : List.of(callerRole, observerRole)) {
            cleanup("delete role " + role,
                    () -> iam.deleteRole(DeleteRoleRequest.builder().roleName(role).build()));
        }
    }

    private static void cleanup(String description, Runnable action) {
        try {
            action.run();
        } catch (Exception e) {
            LOG.warning("Failed to " + description + ": " + e.getMessage());
        }
    }

    private static String roleArn(String roleName) {
        return "arn:aws:iam::000000000000:role/" + roleName;
    }

    private static String instanceProfileArn(String path, String profileName) {
        return "arn:aws:iam::000000000000:instance-profile" + path + profileName;
    }
}
