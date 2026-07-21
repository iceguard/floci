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
import software.amazon.awssdk.services.iam.model.GetRolePolicyRequest;
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

class IamDeleteRolePolicyAuthorizationTest {

    private static final Logger LOG = Logger.getLogger(
            IamDeleteRolePolicyAuthorizationTest.class.getName());
    private static final String TRUST_POLICY = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"
            }]}
            """;
    private static final String INLINE_POLICY = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"
            }]}
            """;

    @Test
    void assumedSessionRequiresExactExistingRoleToDeleteInlinePolicy() {
        String suffix = TestFixtures.uniqueName("delete-role-policy");
        String callerRole = suffix + "-operator";
        String noPermissionRole = suffix + "-observer";
        String allowedRole = suffix + "-allowed-role";
        String deniedRole = suffix + "-denied-role";
        String allowedPolicy = "AllowedInlinePolicyDelete";
        String deniedPolicy = "DeniedInlinePolicyDelete";
        String missingPermissionPolicy = "MissingPermissionInlinePolicyDelete";

        try (IamClient root = TestFixtures.iamClient(); StsClient sts = TestFixtures.stsClient()) {
            String callerRoleArn = createRole(root, callerRole, "/");
            createRole(root, noPermissionRole, "/");
            String allowedRoleArn = createRole(root, allowedRole, "/provisioned/");
            createRole(root, deniedRole, "/protected/");
            putPolicy(root, allowedRole, allowedPolicy, INLINE_POLICY);
            putPolicy(root, deniedRole, deniedPolicy, INLINE_POLICY);
            putPolicy(root, allowedRole, missingPermissionPolicy, INLINE_POLICY);
            putPolicy(root, callerRole, "ScopedInlinePolicyDeletion", """
                    {
                      "Version": "2012-10-17",
                      "Statement": [{
                        "Effect": "Allow",
                        "Action": "iam:DeleteRolePolicy",
                        "Resource": "%s"
                      }]
                    }
                    """.formatted(allowedRoleArn));

            Credentials caller = assumeRole(sts, callerRoleArn, "delete-role-policy-authorized");
            Credentials observer = assumeRole(
                    sts, roleArn(noPermissionRole), "delete-role-policy-observer");
            try (IamClient client = sessionClient(caller);
                    IamClient noPermissionClient = sessionClient(observer)) {
                Assumptions.assumeTrue(enforcementEnabled(noPermissionClient, allowedRole),
                        "IAM enforcement is disabled");

                client.deleteRolePolicy(request -> request
                        .roleName(allowedRole)
                        .policyName(allowedPolicy));
                assertPolicyAbsent(root, allowedRole, allowedPolicy);

                assertAccessDenied(() -> client.deleteRolePolicy(request -> request
                        .roleName(deniedRole)
                        .policyName(deniedPolicy)));
                assertPolicyPresent(root, deniedRole, deniedPolicy);

                assertAccessDenied(() -> noPermissionClient.deleteRolePolicy(request -> request
                        .roleName(allowedRole)
                        .policyName(missingPermissionPolicy)));
                assertPolicyPresent(root, allowedRole, missingPermissionPolicy);
            } finally {
                cleanup(root, callerRole, noPermissionRole, allowedRole, deniedRole,
                        allowedPolicy, deniedPolicy, missingPermissionPolicy);
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

    private static void putPolicy(
            IamClient iam, String roleName, String policyName, String policyDocument) {
        iam.putRolePolicy(PutRolePolicyRequest.builder()
                .roleName(roleName)
                .policyName(policyName)
                .policyDocument(policyDocument)
                .build());
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

    private static void assertPolicyAbsent(IamClient iam, String roleName, String policyName) {
        assertThatThrownBy(() -> iam.getRolePolicy(GetRolePolicyRequest.builder()
                        .roleName(roleName)
                        .policyName(policyName)
                        .build()))
                .isInstanceOf(NoSuchEntityException.class)
                .satisfies(error -> assertThat(((NoSuchEntityException) error).statusCode())
                        .isEqualTo(404));
    }

    private static void assertPolicyPresent(IamClient iam, String roleName, String policyName) {
        var stored = iam.getRolePolicy(GetRolePolicyRequest.builder()
                .roleName(roleName)
                .policyName(policyName)
                .build());
        assertThat(stored.roleName()).isEqualTo(roleName);
        assertThat(stored.policyName()).isEqualTo(policyName);
    }

    private static void cleanup(
            IamClient iam,
            String callerRole,
            String observerRole,
            String allowedRole,
            String deniedRole,
            String allowedPolicy,
            String deniedPolicy,
            String missingPermissionPolicy) {
        cleanup("delete allowed policy", () -> deletePolicy(iam, allowedRole, allowedPolicy));
        cleanup("delete denied policy", () -> deletePolicy(iam, deniedRole, deniedPolicy));
        cleanup("delete missing-permission policy",
                () -> deletePolicy(iam, allowedRole, missingPermissionPolicy));
        cleanup("delete scoped deletion policy",
                () -> deletePolicy(iam, callerRole, "ScopedInlinePolicyDeletion"));
        for (String role : List.of(callerRole, observerRole, allowedRole, deniedRole)) {
            cleanup("delete role " + role,
                    () -> iam.deleteRole(DeleteRoleRequest.builder().roleName(role).build()));
        }
    }

    private static void deletePolicy(IamClient iam, String roleName, String policyName) {
        iam.deleteRolePolicy(DeleteRolePolicyRequest.builder()
                .roleName(roleName)
                .policyName(policyName)
                .build());
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
