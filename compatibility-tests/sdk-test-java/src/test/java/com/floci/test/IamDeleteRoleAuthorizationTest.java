package com.floci.test;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.CreateRoleRequest;
import software.amazon.awssdk.services.iam.model.DeleteRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.DeleteRoleRequest;
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

class IamDeleteRoleAuthorizationTest {

    private static final Logger LOG = Logger.getLogger(IamDeleteRoleAuthorizationTest.class.getName());
    private static final String TRUST_POLICY = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"
            }]}
            """;

    @Test
    void assumedSessionRequiresExactExistingRoleToDeleteRole() {
        String suffix = TestFixtures.uniqueName("delete-role");
        String callerRole = suffix + "-operator";
        String noPermissionRole = suffix + "-observer";
        String allowedRole = suffix + "-allowed-role";
        String deniedRole = suffix + "-denied-role";
        String missingPermissionRole = suffix + "-missing-permission-role";
        String allowedPath = "/provisioned/";
        String deniedPath = "/protected/";

        try (IamClient root = TestFixtures.iamClient(); StsClient sts = TestFixtures.stsClient()) {
            String callerRoleArn = createRole(root, callerRole, "/");
            createRole(root, noPermissionRole, "/");
            String allowedRoleArn = createRole(root, allowedRole, allowedPath);
            createRole(root, deniedRole, deniedPath);
            createRole(root, missingPermissionRole, allowedPath);
            root.putRolePolicy(PutRolePolicyRequest.builder()
                    .roleName(callerRole)
                    .policyName("ScopedRoleDeletion")
                    .policyDocument("""
                            {
                              "Version": "2012-10-17",
                              "Statement": [{
                                "Effect": "Allow",
                                "Action": "iam:DeleteRole",
                                "Resource": "%s"
                              }]
                            }
                            """.formatted(allowedRoleArn))
                    .build());

            Credentials caller = assumeRole(sts, callerRoleArn, "delete-role-authorized");
            Credentials observer = assumeRole(sts, roleArn(noPermissionRole), "delete-role-observer");
            try (IamClient client = sessionClient(caller);
                    IamClient noPermissionClient = sessionClient(observer)) {
                Assumptions.assumeTrue(enforcementEnabled(noPermissionClient, callerRole),
                        "IAM enforcement is disabled");

                client.deleteRole(request -> request.roleName(allowedRole));
                assertRoleAbsent(root, allowedRole);

                assertAccessDenied(() -> client.deleteRole(request -> request.roleName(deniedRole)));
                assertRolePresent(root, deniedRole, deniedPath);

                assertAccessDenied(() -> noPermissionClient.deleteRole(request -> request
                        .roleName(missingPermissionRole)));
                assertRolePresent(root, missingPermissionRole, allowedPath);
            } finally {
                cleanup(root, callerRole, noPermissionRole,
                        allowedRole, deniedRole, missingPermissionRole);
            }
        }
    }

    private static String createRole(IamClient iam, String roleName, String path) {
        return iam.createRole(CreateRoleRequest.builder()
                        .roleName(roleName)
                        .path(path)
                        .assumeRolePolicyDocument(TRUST_POLICY)
                        .build())
                .role().arn();
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

    private static void assertRoleAbsent(IamClient iam, String roleName) {
        assertThatThrownBy(() -> iam.getRole(GetRoleRequest.builder().roleName(roleName).build()))
                .isInstanceOf(NoSuchEntityException.class)
                .satisfies(error -> assertThat(((NoSuchEntityException) error).statusCode())
                        .isEqualTo(404));
    }

    private static void assertRolePresent(IamClient iam, String roleName, String path) {
        var role = iam.getRole(GetRoleRequest.builder().roleName(roleName).build()).role();
        assertThat(role.roleName()).isEqualTo(roleName);
        assertThat(role.path()).isEqualTo(path);
        assertThat(role.arn()).isEqualTo(roleArn(path, roleName));
    }

    private static void cleanup(
            IamClient iam,
            String callerRole,
            String observerRole,
            String allowedRole,
            String deniedRole,
            String missingPermissionRole) {
        cleanup("delete scoped role policy", () -> iam.deleteRolePolicy(
                DeleteRolePolicyRequest.builder()
                        .roleName(callerRole)
                        .policyName("ScopedRoleDeletion")
                        .build()));
        for (String role : List.of(
                callerRole, observerRole, allowedRole, deniedRole, missingPermissionRole)) {
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
        return roleArn("/", roleName);
    }

    private static String roleArn(String path, String roleName) {
        return "arn:aws:iam::000000000000:role" + path + roleName;
    }
}
