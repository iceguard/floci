package com.floci.test;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.CreateAccessKeyRequest;
import software.amazon.awssdk.services.iam.model.CreateUserRequest;
import software.amazon.awssdk.services.iam.model.DeleteAccessKeyRequest;
import software.amazon.awssdk.services.iam.model.DeleteUserPolicyRequest;
import software.amazon.awssdk.services.iam.model.DeleteUserRequest;
import software.amazon.awssdk.services.iam.model.PutUserPolicyRequest;

final class RdsIamTestPrincipal implements AutoCloseable {

    private static final String POLICY_NAME = "rds-db-connect";

    private final IamClient iam;
    private final String userName;
    private final String accessKeyId;
    private final StaticCredentialsProvider credentialsProvider;

    private RdsIamTestPrincipal(IamClient iam, String userName, String accessKeyId,
                                String secretAccessKey) {
        this.iam = iam;
        this.userName = userName;
        this.accessKeyId = accessKeyId;
        this.credentialsProvider = StaticCredentialsProvider.create(
                AwsBasicCredentials.create(accessKeyId, secretAccessKey));
    }

    static RdsIamTestPrincipal create(String databaseResourceId, String databaseUser) {
        IamClient iam = TestFixtures.iamClient();
        String userName = TestFixtures.uniqueName("rds-iam-principal");
        iam.createUser(CreateUserRequest.builder().userName(userName).build());
        var accessKey = iam.createAccessKey(CreateAccessKeyRequest.builder()
                        .userName(userName)
                        .build())
                .accessKey();
        String databaseUserArn = "arn:aws:rds-db:us-east-1:000000000000:dbuser:%s/%s"
                .formatted(databaseResourceId, databaseUser);
        iam.putUserPolicy(PutUserPolicyRequest.builder()
                .userName(userName)
                .policyName(POLICY_NAME)
                .policyDocument("""
                        {
                          "Version": "2012-10-17",
                          "Statement": [{
                            "Effect": "Allow",
                            "Action": "rds-db:connect",
                            "Resource": "%s"
                          }]
                        }
                        """.formatted(databaseUserArn))
                .build());
        return new RdsIamTestPrincipal(
                iam, userName, accessKey.accessKeyId(), accessKey.secretAccessKey());
    }

    StaticCredentialsProvider credentialsProvider() {
        return credentialsProvider;
    }

    @Override
    public void close() {
        try {
            iam.deleteUserPolicy(DeleteUserPolicyRequest.builder()
                    .userName(userName)
                    .policyName(POLICY_NAME)
                    .build());
        } finally {
            try {
                iam.deleteAccessKey(DeleteAccessKeyRequest.builder()
                        .userName(userName)
                        .accessKeyId(accessKeyId)
                        .build());
            } finally {
                try {
                    iam.deleteUser(DeleteUserRequest.builder().userName(userName).build());
                } finally {
                    iam.close();
                }
            }
        }
    }
}
