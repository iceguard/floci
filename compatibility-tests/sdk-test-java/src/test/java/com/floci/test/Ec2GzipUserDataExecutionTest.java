package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.CreateLaunchTemplateRequest;
import software.amazon.awssdk.services.ec2.model.DeleteLaunchTemplateRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstanceAttributeRequest;
import software.amazon.awssdk.services.ec2.model.DescribeLaunchTemplateVersionsRequest;
import software.amazon.awssdk.services.ec2.model.InstanceAttributeName;
import software.amazon.awssdk.services.ec2.model.InstanceStateName;
import software.amazon.awssdk.services.ec2.model.LaunchTemplateSpecification;
import software.amazon.awssdk.services.ec2.model.RequestLaunchTemplateData;
import software.amazon.awssdk.services.ec2.model.RunInstancesRequest;
import software.amazon.awssdk.services.ec2.model.TerminateInstancesRequest;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.CommandInvocationStatus;
import software.amazon.awssdk.services.ssm.model.GetCommandInvocationRequest;
import software.amazon.awssdk.services.ssm.model.GetCommandInvocationResponse;
import software.amazon.awssdk.services.ssm.model.SendCommandRequest;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("EC2 gzip user data execution")
@EnabledIfSystemProperty(named = "floci.ec2.gzip-user-data.enabled", matches = "true")
class Ec2GzipUserDataExecutionTest {

    private static final Duration READY_TIMEOUT = Duration.ofMinutes(2);
    private static final Duration COMMAND_TIMEOUT = Duration.ofMinutes(2);
    private static Ec2Client ec2;
    private static SsmClient ssm;

    @BeforeAll
    static void setup() {
        ec2 = TestFixtures.ec2Client();
        ssm = TestFixtures.ssmClient();
    }

    @AfterAll
    static void cleanupClients() {
        if (ssm != null) {
            ssm.close();
        }
        if (ec2 != null) {
            ec2.close();
        }
    }

    @Test
    void sdkPreservesAndExecutesValidGzipUserData() throws Exception {
        String token = TestFixtures.uniqueName("gzip-user-data");
        String marker = "/tmp/" + token;
        byte[] gzipUserData = gzip("""
                #!/bin/bash
                set -euo pipefail
                printf '%s\\n' > %s
                """.formatted(token, marker));
        String encodedUserData = Base64.getEncoder().encodeToString(gzipUserData);
        String expectedSha256 = sha256(gzipUserData);
        String launchTemplateName = TestFixtures.uniqueName("sdk-gzip-user-data");
        String launchTemplateId = ec2.createLaunchTemplate(CreateLaunchTemplateRequest.builder()
                .launchTemplateName(launchTemplateName)
                .launchTemplateData(RequestLaunchTemplateData.builder()
                        .imageId("ami-ubuntu2404-arm64")
                        .instanceType("t4g.micro")
                        .userData(encodedUserData)
                        .build())
                .build()).launchTemplate().launchTemplateId();
        String instanceId = null;

        Throwable testFailure = null;
        try {
            String describedTemplateUserData = ec2.describeLaunchTemplateVersions(
                    DescribeLaunchTemplateVersionsRequest.builder()
                            .launchTemplateId(launchTemplateId)
                            .versions("1")
                            .build())
                    .launchTemplateVersions().get(0).launchTemplateData().userData();
            assertThat(describedTemplateUserData).isEqualTo(encodedUserData);

            instanceId = ec2.runInstances(RunInstancesRequest.builder()
                    .launchTemplate(LaunchTemplateSpecification.builder()
                            .launchTemplateId(launchTemplateId)
                            .version("1")
                            .build())
                    .minCount(1)
                    .maxCount(1)
                    .build()).instances().get(0).instanceId();
            waitForRunning(instanceId);

            String describedInstanceUserData = ec2.describeInstanceAttribute(
                    DescribeInstanceAttributeRequest.builder()
                            .instanceId(instanceId)
                            .attribute(InstanceAttributeName.USER_DATA)
                            .build()).userData().value();
            assertThat(describedInstanceUserData).isEqualTo(encodedUserData);

            String commandId = ssm.sendCommand(SendCommandRequest.builder()
                            .documentName("AWS-RunShellScript")
                            .instanceIds(instanceId)
                            .parameters(Map.of("commands", List.of(
                                    "set -eu",
                                    "deadline=$((SECONDS + 60))",
                                    "while [ ! -f " + marker + " ] && [ \"$SECONDS\" -lt \"$deadline\" ]; do sleep 1; done",
                                    "test \"$(cat " + marker + ")\" = \"" + token + "\"",
                                    "curl -sf http://169.254.169.254/latest/user-data | sha256sum | awk '{print $1}'")))
                    .timeoutSeconds(90)
                    .build()).command().commandId();
            GetCommandInvocationResponse invocation = waitForCommand(commandId, instanceId);

            assertThat(invocation.status())
                    .withFailMessage("SSM status=%s stdout=%s stderr=%s",
                            invocation.status(),
                            invocation.standardOutputContent(),
                            invocation.standardErrorContent())
                    .isEqualTo(CommandInvocationStatus.SUCCESS);
            assertThat(invocation.standardOutputContent()).contains(expectedSha256);
        } catch (Exception | AssertionError e) {
            testFailure = e;
            throw e;
        } finally {
            Throwable cleanupFailure = cleanup(instanceId, launchTemplateId);
            if (cleanupFailure != null) {
                if (testFailure != null) {
                    testFailure.addSuppressed(cleanupFailure);
                } else {
                    rethrow(cleanupFailure);
                }
            }
        }
    }

    private static Throwable cleanup(String instanceId, String launchTemplateId) {
        Throwable failure = null;
        if (instanceId != null) {
            try {
                ec2.terminateInstances(TerminateInstancesRequest.builder()
                        .instanceIds(instanceId)
                        .build());
                waitForTerminated(instanceId);
            } catch (Exception | AssertionError e) {
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                failure = e;
            }
        }
        try {
            ec2.deleteLaunchTemplate(DeleteLaunchTemplateRequest.builder()
                    .launchTemplateId(launchTemplateId)
                    .build());
        } catch (RuntimeException e) {
            if (failure == null) {
                failure = e;
            } else {
                failure.addSuppressed(e);
            }
        }
        return failure;
    }

    private static void rethrow(Throwable failure) throws Exception {
        if (failure instanceof Exception exception) {
            throw exception;
        }
        if (failure instanceof AssertionError assertionError) {
            throw assertionError;
        }
        throw new AssertionError(failure);
    }

    private static void waitForRunning(String instanceId) throws InterruptedException {
        long deadline = System.nanoTime() + READY_TIMEOUT.toNanos();
        while (System.nanoTime() < deadline) {
            InstanceStateName state = ec2.describeInstances(request -> request.instanceIds(instanceId))
                    .reservations().get(0).instances().get(0).state().name();
            if (state == InstanceStateName.RUNNING) {
                return;
            }
            Thread.sleep(250);
        }
        throw new AssertionError("Instance did not reach running state: " + instanceId);
    }

    private static void waitForTerminated(String instanceId) throws InterruptedException {
        long deadline = System.nanoTime() + READY_TIMEOUT.toNanos();
        while (System.nanoTime() < deadline) {
            InstanceStateName state = ec2.describeInstances(request -> request.instanceIds(instanceId))
                    .reservations().get(0).instances().get(0).state().name();
            if (state == InstanceStateName.TERMINATED) {
                return;
            }
            Thread.sleep(250);
        }
        throw new AssertionError("Instance did not reach terminated state: " + instanceId);
    }

    private static GetCommandInvocationResponse waitForCommand(String commandId, String instanceId)
            throws InterruptedException {
        long deadline = System.nanoTime() + COMMAND_TIMEOUT.toNanos();
        GetCommandInvocationResponse response = null;
        while (System.nanoTime() < deadline) {
            response = ssm.getCommandInvocation(GetCommandInvocationRequest.builder()
                    .commandId(commandId)
                    .instanceId(instanceId)
                    .build());
            if (response.status() != CommandInvocationStatus.PENDING
                    && response.status() != CommandInvocationStatus.IN_PROGRESS
                    && response.status() != CommandInvocationStatus.DELAYED) {
                return response;
            }
            Thread.sleep(250);
        }
        throw new AssertionError("SSM command did not complete: " + response);
    }

    private static byte[] gzip(String value) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
            gzip.write(value.getBytes(StandardCharsets.UTF_8));
        }
        return output.toByteArray();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
