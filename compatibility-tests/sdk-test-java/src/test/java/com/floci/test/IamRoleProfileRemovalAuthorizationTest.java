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
import software.amazon.awssdk.services.iam.model.PutRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.RemoveRoleFromInstanceProfileRequest;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.util.List;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IamRoleProfileRemovalAuthorizationTest {

    private static final Logger LOG = Logger.getLogger(
            IamRoleProfileRemovalAuthorizationTest.class.getName());
    private static final String TRUST_POLICY = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"
            }]}
            """;

    @Test
    void assumedSessionRequiresBothExistingResourcesToRemoveAssociation() {
        String suffix = TestFixtures.uniqueName("remove-role-profile");
        String callerRole = suffix + "-operator";
        String noPermissionRole = suffix + "-observer";
        String allowedRole = suffix + "-allowed-role";
        String deniedRole = suffix + "-denied-role";
        String allowedProfile = suffix + "-allowed-profile";
        String wrongRoleProfile = suffix + "-wrong-role-profile";
        String wrongProfile = suffix + "-wrong-profile";
        String missingPermissionProfile = suffix + "-missing-permission-profile";
        List<String> profiles = List.of(
                allowedProfile, wrongRoleProfile, wrongProfile, missingPermissionProfile);

        try (IamClient root = TestFixtures.iamClient(); StsClient sts = TestFixtures.stsClient()) {
            String callerRoleArn = createRole(root, callerRole);
            createRole(root, noPermissionRole);
            String allowedRoleArn = createRole(root, allowedRole);
            createRole(root, deniedRole);
            String allowedProfileArn = createProfile(root, allowedProfile);
            String wrongRoleProfileArn = createProfile(root, wrongRoleProfile);
            createProfile(root, wrongProfile);
            createProfile(root, missingPermissionProfile);

            addAssociation(root, allowedRole, allowedProfile);
            addAssociation(root, deniedRole, wrongRoleProfile);
            addAssociation(root, allowedRole, wrongProfile);
            addAssociation(root, allowedRole, missingPermissionProfile);
            root.putRolePolicy(PutRolePolicyRequest.builder()
                    .roleName(callerRole)
                    .policyName("ScopedRoleProfileRemoval")
                    .policyDocument("""
                            {
                              "Version": "2012-10-17",
                              "Statement": [{
                                "Effect": "Allow",
                                "Action": "iam:RemoveRoleFromInstanceProfile",
                                "Resource": ["%s", "%s", "%s"]
                              }]
                            }
                            """.formatted(allowedRoleArn, allowedProfileArn, wrongRoleProfileArn))
                    .build());

            Credentials caller = assumeRole(sts, callerRoleArn, "remove-role-profile-authorized");
            Credentials observer = assumeRole(
                    sts, roleArn(noPermissionRole), "remove-role-profile-observer");
            try (IamClient client = sessionClient(caller);
                    IamClient noPermissionClient = sessionClient(observer)) {
                Assumptions.assumeTrue(enforcementEnabled(noPermissionClient, allowedRole),
                        "IAM enforcement is disabled");

                assertAccessDenied(() -> client.removeRoleFromInstanceProfile(request -> request
                        .roleName(deniedRole)
                        .instanceProfileName(wrongRoleProfile)));
                assertAssociation(root, wrongRoleProfile, deniedRole);

                assertAccessDenied(() -> client.removeRoleFromInstanceProfile(request -> request
                        .roleName(allowedRole)
                        .instanceProfileName(wrongProfile)));
                assertAssociation(root, wrongProfile, allowedRole);

                assertAccessDenied(() -> noPermissionClient.removeRoleFromInstanceProfile(request -> request
                        .roleName(allowedRole)
                        .instanceProfileName(missingPermissionProfile)));
                assertAssociation(root, missingPermissionProfile, allowedRole);

                client.removeRoleFromInstanceProfile(request -> request
                        .roleName(allowedRole)
                        .instanceProfileName(allowedProfile));
                assertThat(root.getInstanceProfile(GetInstanceProfileRequest.builder()
                                .instanceProfileName(allowedProfile)
                                .build())
                        .instanceProfile().roles()).isEmpty();
            } finally {
                cleanup(root, callerRole, noPermissionRole, allowedRole, deniedRole, profiles);
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

    private static String createProfile(IamClient iam, String profileName) {
        return iam.createInstanceProfile(CreateInstanceProfileRequest.builder()
                        .instanceProfileName(profileName)
                        .build())
                .instanceProfile().arn();
    }

    private static void addAssociation(IamClient iam, String roleName, String profileName) {
        iam.addRoleToInstanceProfile(request -> request
                .roleName(roleName)
                .instanceProfileName(profileName));
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

    private static void assertAssociation(IamClient iam, String profileName, String roleName) {
        var roles = iam.getInstanceProfile(GetInstanceProfileRequest.builder()
                        .instanceProfileName(profileName)
                        .build())
                .instanceProfile().roles();
        assertThat(roles).singleElement().extracting(role -> role.roleName()).isEqualTo(roleName);
    }

    private static void cleanup(
            IamClient iam, String callerRole, String observerRole,
            String allowedRole, String deniedRole, List<String> profiles) {
        for (String profile : profiles) {
            cleanup("empty instance profile " + profile, () -> {
                var roles = iam.getInstanceProfile(GetInstanceProfileRequest.builder()
                                .instanceProfileName(profile)
                                .build())
                        .instanceProfile().roles();
                for (var role : roles) {
                    iam.removeRoleFromInstanceProfile(RemoveRoleFromInstanceProfileRequest.builder()
                            .roleName(role.roleName())
                            .instanceProfileName(profile)
                            .build());
                }
            });
            cleanup("delete instance profile " + profile,
                    () -> iam.deleteInstanceProfile(DeleteInstanceProfileRequest.builder()
                            .instanceProfileName(profile)
                            .build()));
        }
        cleanup("delete scoped removal policy", () -> iam.deleteRolePolicy(
                DeleteRolePolicyRequest.builder()
                        .roleName(callerRole)
                        .policyName("ScopedRoleProfileRemoval")
                        .build()));
        for (String role : List.of(callerRole, observerRole, allowedRole, deniedRole)) {
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
}
