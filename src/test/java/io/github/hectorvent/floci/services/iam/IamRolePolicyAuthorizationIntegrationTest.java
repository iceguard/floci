package io.github.hectorvent.floci.services.iam;

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
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.IamException;
import software.amazon.awssdk.services.iam.model.NoSuchEntityException;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(IamRolePolicyAuthorizationIntegrationTest.IamEnforcementProfile.class)
class IamRolePolicyAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";
    private static final String ALLOWED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess";
    private static final String DENIED_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess";
    private static final String TRUST_POLICY = """
            {
              "Version": "2012-10-17",
              "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole"
              }]
            }
            """;

    @Test
    void authorizesExactCreateAttachAndDetachRoleResources() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "RolePolicyOperator" + suffix;
        String allowedRole = "AllowedWorkload" + suffix;
        String deniedRole = "DeniedWorkload" + suffix;
        String deniedCreateRole = "DeniedCreate" + suffix;
        String allowedRoleArn = roleArn("/provisioned/", allowedRole);

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, deniedRole, "/protected/").statusCode(200);
        putRolePolicy(callerRole, "ScopedRolePolicyOperations", """
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {
                      "Effect": "Allow",
                      "Action": "iam:CreateRole",
                      "Resource": "%s"
                    },
                    {
                      "Effect": "Allow",
                      "Action": ["iam:AttachRolePolicy", "iam:DetachRolePolicy"],
                      "Resource": "%s",
                      "Condition": {
                        "ArnEquals": {"iam:PolicyARN": "%s"}
                      }
                    }
                  ]
                }
                """.formatted(allowedRoleArn, allowedRoleArn, ALLOWED_POLICY_ARN));
        SessionCredentials credentials = assumeRole(callerRole);

        createRole(credentials, allowedRole, "/provisioned/")
                .statusCode(200)
                .body(containsString(allowedRoleArn));
        rolePolicyRequest(ACCOUNT_ID, "AttachRolePolicy", deniedRole, ALLOWED_POLICY_ARN)
                .statusCode(200);
        createRole(credentials, deniedCreateRole, "/protected/")
                .statusCode(403)
                .body(containsString("iam:CreateRole"));

        rolePolicyRequest(credentials, "AttachRolePolicy", allowedRole, ALLOWED_POLICY_ARN)
                .statusCode(200);
        rolePolicyRequest(credentials, "AttachRolePolicy", deniedRole, ALLOWED_POLICY_ARN)
                .statusCode(403)
                .body(containsString("iam:AttachRolePolicy"));
        rolePolicyRequest(credentials, "AttachRolePolicy", allowedRole, DENIED_POLICY_ARN)
                .statusCode(403)
                .body(containsString("iam:AttachRolePolicy"));
        listAttachedRolePolicies(allowedRole)
                .statusCode(200)
                .body(containsString(ALLOWED_POLICY_ARN))
                .body(not(containsString(DENIED_POLICY_ARN)));

        rolePolicyRequest(ACCOUNT_ID, "AttachRolePolicy", allowedRole, DENIED_POLICY_ARN)
                .statusCode(200);
        rolePolicyRequest(credentials, "DetachRolePolicy", allowedRole, DENIED_POLICY_ARN)
                .statusCode(403)
                .body(containsString("iam:DetachRolePolicy"));
        rolePolicyRequest(credentials, "DetachRolePolicy", deniedRole, ALLOWED_POLICY_ARN)
                .statusCode(403)
                .body(containsString("iam:DetachRolePolicy"));
        listAttachedRolePolicies(deniedRole)
                .statusCode(200)
                .body(containsString(ALLOWED_POLICY_ARN));
        rolePolicyRequest(credentials, "DetachRolePolicy", allowedRole, ALLOWED_POLICY_ARN)
                .statusCode(200);
        listAttachedRolePolicies(allowedRole)
                .statusCode(200)
                .body(not(containsString(ALLOWED_POLICY_ARN)))
                .body(containsString(DENIED_POLICY_ARN));
    }

    @Test
    void authorizesPutRolePolicyForExactExistingRoleArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "InlinePolicyOperator" + suffix;
        String noPermissionRole = "InlinePolicyObserver" + suffix;
        String allowedRole = "AllowedInlinePolicy" + suffix;
        String deniedRole = "DeniedInlinePolicy" + suffix;
        String allowedRoleArn = roleArn("/provisioned/", allowedRole);
        String allowedPolicyName = "AllowedInlinePolicy";
        String deniedPolicyName = "DeniedInlinePolicy";
        String missingPermissionPolicyName = "MissingPermissionInlinePolicy";
        String inlinePolicyDocument = """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:ListAllMyBuckets",
                    "Resource": "*"
                  }]
                }
                """;

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, noPermissionRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, allowedRole, "/provisioned/").statusCode(200);
        createRole(ACCOUNT_ID, deniedRole, "/protected/").statusCode(200);
        putRolePolicy(callerRole, "ScopedInlinePolicyOperations", """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:PutRolePolicy",
                    "Resource": "%s"
                  }]
                }
                """.formatted(allowedRoleArn));

        SessionCredentials credentials = assumeRole(callerRole);
        SessionCredentials noPermissionCredentials = assumeRole(noPermissionRole);
        try (IamClient root = iamClient(ACCOUNT_ID);
                IamClient client = iamClient(credentials);
                IamClient noPermissionClient = iamClient(noPermissionCredentials)) {
            client.putRolePolicy(request -> request
                    .roleName(allowedRole)
                    .policyName(allowedPolicyName)
                    .policyDocument(inlinePolicyDocument));

            var stored = root.getRolePolicy(request -> request
                    .roleName(allowedRole)
                    .policyName(allowedPolicyName));
            assertEquals(allowedPolicyName, stored.policyName());
            assertTrue(stored.policyDocument().contains("s3:ListAllMyBuckets"));

            IamException wrongRole = assertThrows(IamException.class,
                    () -> client.putRolePolicy(request -> request
                            .roleName(deniedRole)
                            .policyName(deniedPolicyName)
                            .policyDocument(inlinePolicyDocument)));
            assertAccessDenied(wrongRole, "iam:PutRolePolicy");
            assertPolicyAbsent(root, deniedRole, deniedPolicyName);

            IamException missingPermission = assertThrows(IamException.class,
                    () -> noPermissionClient.putRolePolicy(request -> request
                            .roleName(allowedRole)
                            .policyName(missingPermissionPolicyName)
                            .policyDocument(inlinePolicyDocument)));
            assertAccessDenied(missingPermission, "iam:PutRolePolicy");
            assertPolicyAbsent(root, allowedRole, missingPermissionPolicyName);
        }
    }

    @Test
    void authorizesDeleteRolePolicyForExactExistingRoleArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "InlinePolicyDeleteOperator" + suffix;
        String noPermissionRole = "InlinePolicyDeleteObserver" + suffix;
        String allowedRole = "AllowedInlinePolicyDelete" + suffix;
        String deniedRole = "DeniedInlinePolicyDelete" + suffix;
        String allowedRoleArn = roleArn("/provisioned/", allowedRole);
        String allowedPolicyName = "AllowedInlinePolicyDelete";
        String deniedPolicyName = "DeniedInlinePolicyDelete";
        String missingPermissionPolicyName = "MissingPermissionInlinePolicyDelete";
        String inlinePolicyDocument = """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:ListAllMyBuckets",
                    "Resource": "*"
                  }]
                }
                """;

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, noPermissionRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, allowedRole, "/provisioned/").statusCode(200);
        createRole(ACCOUNT_ID, deniedRole, "/protected/").statusCode(200);
        putRolePolicy(allowedRole, allowedPolicyName, inlinePolicyDocument);
        putRolePolicy(deniedRole, deniedPolicyName, inlinePolicyDocument);
        putRolePolicy(allowedRole, missingPermissionPolicyName, inlinePolicyDocument);
        putRolePolicy(callerRole, "ScopedInlinePolicyDeletion", """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:DeleteRolePolicy",
                    "Resource": "%s"
                  }]
                }
                """.formatted(allowedRoleArn));

        SessionCredentials credentials = assumeRole(callerRole);
        SessionCredentials noPermissionCredentials = assumeRole(noPermissionRole);
        try (IamClient root = iamClient(ACCOUNT_ID);
                IamClient client = iamClient(credentials);
                IamClient noPermissionClient = iamClient(noPermissionCredentials)) {
            client.deleteRolePolicy(request -> request
                    .roleName(allowedRole)
                    .policyName(allowedPolicyName));
            assertPolicyAbsent(root, allowedRole, allowedPolicyName);

            IamException wrongRole = assertThrows(IamException.class,
                    () -> client.deleteRolePolicy(request -> request
                            .roleName(deniedRole)
                            .policyName(deniedPolicyName)));
            assertAccessDenied(wrongRole, "iam:DeleteRolePolicy");
            assertPolicyPresent(root, deniedRole, deniedPolicyName);

            IamException missingPermission = assertThrows(IamException.class,
                    () -> noPermissionClient.deleteRolePolicy(request -> request
                            .roleName(allowedRole)
                            .policyName(missingPermissionPolicyName)));
            assertAccessDenied(missingPermission, "iam:DeleteRolePolicy");
            assertPolicyPresent(root, allowedRole, missingPermissionPolicyName);
        }
    }

    @Test
    void authorizesDeleteRoleForExactExistingRoleArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "RoleDeleteOperator" + suffix;
        String noPermissionRole = "RoleDeleteObserver" + suffix;
        String allowedRole = "AllowedRoleDelete" + suffix;
        String deniedRole = "DeniedRoleDelete" + suffix;
        String missingPermissionRole = "MissingPermissionRoleDelete" + suffix;
        String allowedPath = "/provisioned/";
        String deniedPath = "/protected/";
        String allowedRoleArn = roleArn(allowedPath, allowedRole);

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, noPermissionRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, allowedRole, allowedPath).statusCode(200);
        createRole(ACCOUNT_ID, deniedRole, deniedPath).statusCode(200);
        createRole(ACCOUNT_ID, missingPermissionRole, allowedPath).statusCode(200);
        putRolePolicy(callerRole, "ScopedRoleDeletion", """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:DeleteRole",
                    "Resource": "%s"
                  }]
                }
                """.formatted(allowedRoleArn));

        SessionCredentials credentials = assumeRole(callerRole);
        SessionCredentials noPermissionCredentials = assumeRole(noPermissionRole);
        try (IamClient root = iamClient(ACCOUNT_ID);
                IamClient client = iamClient(credentials);
                IamClient noPermissionClient = iamClient(noPermissionCredentials)) {
            client.deleteRole(request -> request.roleName(allowedRole));
            assertRoleAbsent(root, allowedRole);

            IamException wrongRole = assertThrows(IamException.class,
                    () -> client.deleteRole(request -> request.roleName(deniedRole)));
            assertAccessDenied(wrongRole, "iam:DeleteRole");
            assertRolePresent(root, deniedRole, deniedPath);

            IamException missingPermission = assertThrows(IamException.class,
                    () -> noPermissionClient.deleteRole(request -> request
                            .roleName(missingPermissionRole)));
            assertAccessDenied(missingPermission, "iam:DeleteRole");
            assertRolePresent(root, missingPermissionRole, allowedPath);
        }
    }

    @Test
    void authorizesCreateInstanceProfileForExactFutureArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "InstanceProfileOperator" + suffix;
        String noPermissionRole = "InstanceProfileObserver" + suffix;
        String allowedProfile = "AllowedInstanceProfile" + suffix;
        String deniedProfile = "DeniedInstanceProfile" + suffix;
        String missingPermissionProfile = "MissingPermissionInstanceProfile" + suffix;
        String path = "/provisioned/";
        String allowedProfileArn = instanceProfileArn(path, allowedProfile);

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, noPermissionRole, "/").statusCode(200);
        putRolePolicy(callerRole, "ScopedInstanceProfileCreation", """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:CreateInstanceProfile",
                    "Resource": "%s"
                  }]
                }
                """.formatted(allowedProfileArn));

        SessionCredentials credentials = assumeRole(callerRole);
        SessionCredentials noPermissionCredentials = assumeRole(noPermissionRole);
        try (IamClient root = iamClient(ACCOUNT_ID);
                IamClient client = iamClient(credentials);
                IamClient noPermissionClient = iamClient(noPermissionCredentials)) {
            var created = client.createInstanceProfile(request -> request
                    .instanceProfileName(allowedProfile)
                    .path(path));
            assertEquals(allowedProfile, created.instanceProfile().instanceProfileName());
            assertEquals(path, created.instanceProfile().path());
            assertEquals(allowedProfileArn, created.instanceProfile().arn());

            var stored = root.getInstanceProfile(request -> request
                    .instanceProfileName(allowedProfile));
            assertEquals(allowedProfile, stored.instanceProfile().instanceProfileName());
            assertEquals(path, stored.instanceProfile().path());
            assertEquals(allowedProfileArn, stored.instanceProfile().arn());

            IamException wrongProfile = assertThrows(IamException.class,
                    () -> client.createInstanceProfile(request -> request
                            .instanceProfileName(deniedProfile)
                            .path(path)));
            assertAccessDenied(wrongProfile, "iam:CreateInstanceProfile");
            assertInstanceProfileAbsent(root, deniedProfile);

            IamException missingPermission = assertThrows(IamException.class,
                    () -> noPermissionClient.createInstanceProfile(request -> request
                            .instanceProfileName(missingPermissionProfile)
                            .path(path)));
            assertAccessDenied(missingPermission, "iam:CreateInstanceProfile");
            assertInstanceProfileAbsent(root, missingPermissionProfile);
        }
    }

    @Test
    void authorizesDeleteInstanceProfileForExactExistingProfileArn() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "InstanceProfileDeleteOperator" + suffix;
        String noPermissionRole = "InstanceProfileDeleteObserver" + suffix;
        String allowedProfile = "AllowedInstanceProfileDelete" + suffix;
        String deniedProfile = "DeniedInstanceProfileDelete" + suffix;
        String missingPermissionProfile = "MissingPermissionInstanceProfileDelete" + suffix;
        String path = "/provisioned/";
        String allowedProfileArn = instanceProfileArn(path, allowedProfile);

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, noPermissionRole, "/").statusCode(200);
        putRolePolicy(callerRole, "ScopedInstanceProfileDeletion", """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:DeleteInstanceProfile",
                    "Resource": "%s"
                  }]
                }
                """.formatted(allowedProfileArn));

        SessionCredentials credentials = assumeRole(callerRole);
        SessionCredentials noPermissionCredentials = assumeRole(noPermissionRole);
        try (IamClient root = iamClient(ACCOUNT_ID);
                IamClient client = iamClient(credentials);
                IamClient noPermissionClient = iamClient(noPermissionCredentials)) {
            for (String profile : new String[] {
                    allowedProfile, deniedProfile, missingPermissionProfile}) {
                root.createInstanceProfile(request -> request
                        .instanceProfileName(profile)
                        .path(path));
            }

            client.deleteInstanceProfile(request -> request.instanceProfileName(allowedProfile));
            assertInstanceProfileAbsent(root, allowedProfile);

            IamException wrongProfile = assertThrows(IamException.class,
                    () -> client.deleteInstanceProfile(request -> request
                            .instanceProfileName(deniedProfile)));
            assertAccessDenied(wrongProfile, "iam:DeleteInstanceProfile");
            assertInstanceProfilePresent(root, deniedProfile, path);

            IamException missingPermission = assertThrows(IamException.class,
                    () -> noPermissionClient.deleteInstanceProfile(request -> request
                            .instanceProfileName(missingPermissionProfile)));
            assertAccessDenied(missingPermission, "iam:DeleteInstanceProfile");
            assertInstanceProfilePresent(root, missingPermissionProfile, path);
        }
    }

    @Test
    void authorizesAddRoleToInstanceProfileForBothExactExistingArns() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "RoleProfileOperator" + suffix;
        String noPermissionRole = "RoleProfileObserver" + suffix;
        String allowedRole = "AllowedProfileRole" + suffix;
        String deniedRole = "DeniedProfileRole" + suffix;
        String allowedProfile = "AllowedRoleProfile" + suffix;
        String deniedProfile = "DeniedRoleProfile" + suffix;
        String missingPermissionProfile = "MissingPermissionRoleProfile" + suffix;
        String path = "/provisioned/";
        String allowedRoleArn = roleArn(path, allowedRole);
        String allowedProfileArn = instanceProfileArn(path, allowedProfile);

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, noPermissionRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, allowedRole, path).statusCode(200);
        createRole(ACCOUNT_ID, deniedRole, path).statusCode(200);
        putRolePolicy(callerRole, "ScopedRoleProfileAssociation", """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:AddRoleToInstanceProfile",
                    "Resource": ["%s", "%s"]
                  }]
                }
                """.formatted(allowedRoleArn, allowedProfileArn));

        SessionCredentials credentials = assumeRole(callerRole);
        SessionCredentials noPermissionCredentials = assumeRole(noPermissionRole);
        try (IamClient root = iamClient(ACCOUNT_ID);
                IamClient client = iamClient(credentials);
                IamClient noPermissionClient = iamClient(noPermissionCredentials)) {
            root.createInstanceProfile(request -> request
                    .instanceProfileName(allowedProfile)
                    .path(path));
            root.createInstanceProfile(request -> request
                    .instanceProfileName(deniedProfile)
                    .path(path));
            root.createInstanceProfile(request -> request
                    .instanceProfileName(missingPermissionProfile)
                    .path(path));

            IamException wrongRole = assertThrows(IamException.class,
                    () -> client.addRoleToInstanceProfile(request -> request
                            .roleName(deniedRole)
                            .instanceProfileName(allowedProfile)));
            assertAccessDenied(wrongRole, "iam:AddRoleToInstanceProfile");
            assertInstanceProfileHasNoRoles(root, allowedProfile);

            IamException wrongProfile = assertThrows(IamException.class,
                    () -> client.addRoleToInstanceProfile(request -> request
                            .roleName(allowedRole)
                            .instanceProfileName(deniedProfile)));
            assertAccessDenied(wrongProfile, "iam:AddRoleToInstanceProfile");
            assertInstanceProfileHasNoRoles(root, deniedProfile);

            IamException missingPermission = assertThrows(IamException.class,
                    () -> noPermissionClient.addRoleToInstanceProfile(request -> request
                            .roleName(allowedRole)
                            .instanceProfileName(missingPermissionProfile)));
            assertAccessDenied(missingPermission, "iam:AddRoleToInstanceProfile");
            assertInstanceProfileHasNoRoles(root, missingPermissionProfile);

            client.addRoleToInstanceProfile(request -> request
                    .roleName(allowedRole)
                    .instanceProfileName(allowedProfile));

            var stored = root.getInstanceProfile(request -> request
                    .instanceProfileName(allowedProfile));
            assertEquals(1, stored.instanceProfile().roles().size());
            assertEquals(allowedRole, stored.instanceProfile().roles().getFirst().roleName());
            assertEquals(allowedRoleArn, stored.instanceProfile().roles().getFirst().arn());
        }
    }

    @Test
    void authorizesRemoveRoleFromInstanceProfileForBothExactExistingArns() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String callerRole = "RoleProfileRemovalOperator" + suffix;
        String noPermissionRole = "RoleProfileRemovalObserver" + suffix;
        String allowedRole = "AllowedProfileRemovalRole" + suffix;
        String deniedRole = "DeniedProfileRemovalRole" + suffix;
        String allowedProfile = "AllowedRoleRemovalProfile" + suffix;
        String wrongRoleProfile = "WrongRoleRemovalProfile" + suffix;
        String wrongProfile = "WrongRemovalProfile" + suffix;
        String missingPermissionProfile = "MissingPermissionRemovalProfile" + suffix;
        String path = "/provisioned/";
        String allowedRoleArn = roleArn(path, allowedRole);
        String allowedProfileArn = instanceProfileArn(path, allowedProfile);
        String wrongRoleProfileArn = instanceProfileArn(path, wrongRoleProfile);

        createRole(ACCOUNT_ID, callerRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, noPermissionRole, "/").statusCode(200);
        createRole(ACCOUNT_ID, allowedRole, path).statusCode(200);
        createRole(ACCOUNT_ID, deniedRole, path).statusCode(200);
        putRolePolicy(callerRole, "ScopedRoleProfileRemoval", """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:RemoveRoleFromInstanceProfile",
                    "Resource": ["%s", "%s", "%s"]
                  }]
                }
                """.formatted(allowedRoleArn, allowedProfileArn, wrongRoleProfileArn));

        SessionCredentials credentials = assumeRole(callerRole);
        SessionCredentials noPermissionCredentials = assumeRole(noPermissionRole);
        try (IamClient root = iamClient(ACCOUNT_ID);
                IamClient client = iamClient(credentials);
                IamClient noPermissionClient = iamClient(noPermissionCredentials)) {
            for (String profile : new String[] {
                    allowedProfile, wrongRoleProfile, wrongProfile, missingPermissionProfile}) {
                root.createInstanceProfile(request -> request
                        .instanceProfileName(profile)
                        .path(path));
            }
            root.addRoleToInstanceProfile(request -> request
                    .roleName(allowedRole)
                    .instanceProfileName(allowedProfile));
            root.addRoleToInstanceProfile(request -> request
                    .roleName(deniedRole)
                    .instanceProfileName(wrongRoleProfile));
            root.addRoleToInstanceProfile(request -> request
                    .roleName(allowedRole)
                    .instanceProfileName(wrongProfile));
            root.addRoleToInstanceProfile(request -> request
                    .roleName(allowedRole)
                    .instanceProfileName(missingPermissionProfile));

            IamException wrongRole = assertThrows(IamException.class,
                    () -> client.removeRoleFromInstanceProfile(request -> request
                            .roleName(deniedRole)
                            .instanceProfileName(wrongRoleProfile)));
            assertAccessDenied(wrongRole, "iam:RemoveRoleFromInstanceProfile");
            assertInstanceProfileHasRole(root, wrongRoleProfile, deniedRole);

            IamException deniedProfile = assertThrows(IamException.class,
                    () -> client.removeRoleFromInstanceProfile(request -> request
                            .roleName(allowedRole)
                            .instanceProfileName(wrongProfile)));
            assertAccessDenied(deniedProfile, "iam:RemoveRoleFromInstanceProfile");
            assertInstanceProfileHasRole(root, wrongProfile, allowedRole);

            IamException missingPermission = assertThrows(IamException.class,
                    () -> noPermissionClient.removeRoleFromInstanceProfile(request -> request
                            .roleName(allowedRole)
                            .instanceProfileName(missingPermissionProfile)));
            assertAccessDenied(missingPermission, "iam:RemoveRoleFromInstanceProfile");
            assertInstanceProfileHasRole(root, missingPermissionProfile, allowedRole);

            client.removeRoleFromInstanceProfile(request -> request
                    .roleName(allowedRole)
                    .instanceProfileName(allowedProfile));
            assertInstanceProfileHasNoRoles(root, allowedProfile);
        }
    }

    private static IamClient iamClient(String accessKeyId) {
        return IamClient.builder()
                .endpointOverride(URI.create("http://localhost:" + RestAssured.port))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(accessKeyId, "test-secret-key")))
                .build();
    }

    private static IamClient iamClient(SessionCredentials credentials) {
        return IamClient.builder()
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

    private static void assertAccessDenied(IamException exception, String action) {
        assertEquals(403, exception.statusCode());
        assertEquals("AccessDenied", exception.awsErrorDetails().errorCode());
        assertTrue(exception.getMessage().contains(action));
        assertNotNull(exception.requestId());
    }

    private static void assertPolicyAbsent(IamClient root, String roleName, String policyName) {
        NoSuchEntityException missing = assertThrows(NoSuchEntityException.class,
                () -> root.getRolePolicy(request -> request
                        .roleName(roleName)
                        .policyName(policyName)));
        assertEquals(404, missing.statusCode());
        assertEquals("NoSuchEntity", missing.awsErrorDetails().errorCode());
    }

    private static void assertPolicyPresent(IamClient root, String roleName, String policyName) {
        var stored = root.getRolePolicy(request -> request
                .roleName(roleName)
                .policyName(policyName));
        assertEquals(roleName, stored.roleName());
        assertEquals(policyName, stored.policyName());
    }

    private static void assertRoleAbsent(IamClient root, String roleName) {
        NoSuchEntityException missing = assertThrows(NoSuchEntityException.class,
                () -> root.getRole(request -> request.roleName(roleName)));
        assertEquals(404, missing.statusCode());
        assertEquals("NoSuchEntity", missing.awsErrorDetails().errorCode());
    }

    private static void assertRolePresent(IamClient root, String roleName, String path) {
        var stored = root.getRole(request -> request.roleName(roleName));
        assertEquals(roleName, stored.role().roleName());
        assertEquals(path, stored.role().path());
        assertEquals(roleArn(path, roleName), stored.role().arn());
    }

    private static void assertInstanceProfileAbsent(IamClient root, String instanceProfileName) {
        NoSuchEntityException missing = assertThrows(NoSuchEntityException.class,
                () -> root.getInstanceProfile(request -> request
                        .instanceProfileName(instanceProfileName)));
        assertEquals(404, missing.statusCode());
        assertEquals("NoSuchEntity", missing.awsErrorDetails().errorCode());
    }

    private static void assertInstanceProfilePresent(
            IamClient root, String instanceProfileName, String path) {
        var stored = root.getInstanceProfile(request -> request
                .instanceProfileName(instanceProfileName));
        assertEquals(instanceProfileName, stored.instanceProfile().instanceProfileName());
        assertEquals(path, stored.instanceProfile().path());
        assertEquals(instanceProfileArn(path, instanceProfileName), stored.instanceProfile().arn());
    }

    private static void assertInstanceProfileHasNoRoles(IamClient root, String instanceProfileName) {
        var stored = root.getInstanceProfile(request -> request
                .instanceProfileName(instanceProfileName));
        assertTrue(stored.instanceProfile().roles().isEmpty());
    }

    private static void assertInstanceProfileHasRole(
            IamClient root, String instanceProfileName, String roleName) {
        var stored = root.getInstanceProfile(request -> request
                .instanceProfileName(instanceProfileName));
        assertEquals(1, stored.instanceProfile().roles().size());
        assertEquals(roleName, stored.instanceProfile().roles().getFirst().roleName());
    }

    private static io.restassured.response.ValidatableResponse createRole(
            String accessKeyId, String roleName, String path) {
        return queryRequest(accessKeyId, "iam", Map.of(
                "Action", "CreateRole",
                "RoleName", roleName,
                "Path", path,
                "AssumeRolePolicyDocument", TRUST_POLICY));
    }

    private static io.restassured.response.ValidatableResponse createRole(
            SessionCredentials credentials, String roleName, String path) {
        return queryRequest(credentials, "iam", Map.of(
                "Action", "CreateRole",
                "RoleName", roleName,
                "Path", path,
                "AssumeRolePolicyDocument", TRUST_POLICY));
    }

    private static void putRolePolicy(String roleName, String policyName, String policyDocument) {
        queryRequest(ACCOUNT_ID, "iam", Map.of(
                "Action", "PutRolePolicy",
                "RoleName", roleName,
                "PolicyName", policyName,
                "PolicyDocument", policyDocument)).statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        var response = queryRequest(ACCOUNT_ID, "sts", Map.of(
                "Action", "AssumeRole",
                "RoleArn", roleArn("/", roleName),
                "RoleSessionName", "role-policy-authorization"))
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SecretAccessKey"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static io.restassured.response.ValidatableResponse rolePolicyRequest(
            String accessKeyId, String action, String roleName, String policyArn) {
        return queryRequest(accessKeyId, "iam", Map.of(
                "Action", action,
                "RoleName", roleName,
                "PolicyArn", policyArn));
    }

    private static io.restassured.response.ValidatableResponse rolePolicyRequest(
            SessionCredentials credentials, String action, String roleName, String policyArn) {
        return queryRequest(credentials, "iam", Map.of(
                "Action", action,
                "RoleName", roleName,
                "PolicyArn", policyArn));
    }

    private static io.restassured.response.ValidatableResponse listAttachedRolePolicies(String roleName) {
        return queryRequest(ACCOUNT_ID, "iam", Map.of(
                "Action", "ListAttachedRolePolicies",
                "RoleName", roleName));
    }

    private static io.restassured.response.ValidatableResponse queryRequest(
            String accessKeyId, String service, Map<String, String> parameters) {
        String body = parameters.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
        return given()
                .contentType("application/x-www-form-urlencoded; charset=UTF-8")
                .body(body)
                .header("Authorization", auth(accessKeyId, service))
        .when()
                .post("/")
        .then();
    }

    private static io.restassured.response.ValidatableResponse queryRequest(
            SessionCredentials credentials, String service, Map<String, String> parameters) {
        String body = parameters.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
        return given()
                .contentType("application/x-www-form-urlencoded; charset=UTF-8")
                .body(body)
                .header("Authorization", auth(credentials.accessKeyId(), service))
                .header("X-Amz-Security-Token", credentials.sessionToken())
        .when()
                .post("/")
        .then();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String roleArn(String path, String roleName) {
        return "arn:aws:iam::" + ACCOUNT_ID + ":role" + path + roleName;
    }

    private static String instanceProfileArn(String path, String instanceProfileName) {
        return "arn:aws:iam::" + ACCOUNT_ID + ":instance-profile" + path + instanceProfileName;
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260719/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private record SessionCredentials(String accessKeyId, String secretAccessKey, String sessionToken) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
