package com.floci.test;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;

import static org.assertj.core.api.Assertions.assertThat;

class CloudWatchLogsKmsKeyTest {

    @Test
    void createLogGroupPreservesKmsKeyId() {
        String groupName = "/test/" + TestFixtures.uniqueName("kms-log-group");
        String kmsKeyId = "arn:aws:kms:us-east-1:000000000000:key/observability";
        try (CloudWatchLogsClient logs = TestFixtures.cloudWatchLogsClient()) {
            boolean created = false;
            try {
                logs.createLogGroup(request -> request
                        .logGroupName(groupName)
                        .kmsKeyId(kmsKeyId));
                created = true;

                assertThat(logs.describeLogGroups(request -> request.logGroupNamePrefix(groupName)).logGroups())
                        .singleElement()
                        .satisfies(group -> {
                            assertThat(group.logGroupName()).isEqualTo(groupName);
                            assertThat(group.kmsKeyId()).isEqualTo(kmsKeyId);
                        });
            } finally {
                if (created) {
                    logs.deleteLogGroup(request -> request.logGroupName(groupName));
                }
            }
        }
    }
}
