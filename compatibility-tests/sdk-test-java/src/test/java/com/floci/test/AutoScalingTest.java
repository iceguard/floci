package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.autoscaling.AutoScalingClient;
import software.amazon.awssdk.services.autoscaling.model.AttachInstancesRequest;
import software.amazon.awssdk.services.autoscaling.model.AutoScalingException;
import software.amazon.awssdk.services.autoscaling.model.CreateAutoScalingGroupRequest;
import software.amazon.awssdk.services.autoscaling.model.CreateLaunchConfigurationRequest;
import software.amazon.awssdk.services.autoscaling.model.DeleteAutoScalingGroupRequest;
import software.amazon.awssdk.services.autoscaling.model.DesiredConfiguration;
import software.amazon.awssdk.services.autoscaling.model.DescribeInstanceRefreshesRequest;
import software.amazon.awssdk.services.autoscaling.model.DescribeAutoScalingGroupsRequest;
import software.amazon.awssdk.services.autoscaling.model.RefreshPreferences;
import software.amazon.awssdk.services.autoscaling.model.LaunchTemplateSpecification;
import software.amazon.awssdk.services.autoscaling.model.StartInstanceRefreshRequest;
import software.amazon.awssdk.services.autoscaling.model.UpdateAutoScalingGroupRequest;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.CreateLaunchTemplateRequest;
import software.amazon.awssdk.services.ec2.model.CreateLaunchTemplateVersionRequest;
import software.amazon.awssdk.services.ec2.model.DeleteLaunchTemplateRequest;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.InstanceStateName;
import software.amazon.awssdk.services.ec2.model.RequestLaunchTemplateData;
import software.amazon.awssdk.services.ec2.model.RunInstancesRequest;
import software.amazon.awssdk.services.ec2.model.TerminateInstancesRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2Client;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.CreateTargetGroupRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.DeleteTargetGroupRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.DeregisterTargetsRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.DescribeTargetHealthRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ProtocolEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.TargetDescription;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.TargetHealthDescription;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.TargetTypeEnum;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Auto Scaling")
class AutoScalingTest {

    private static final System.Logger LOG = System.getLogger(AutoScalingTest.class.getName());

    private static final String MISSING_LAUNCH_TEMPLATE_IMAGE_ID_MESSAGE =
            "You must use a valid fully-formed launch template. The request must contain the parameter ImageId";
    private static final String INVALID_LAUNCH_CONFIGURATION_PARAMETERS_MESSAGE =
            "Valid requests must contain either the InstanceID parameter "
                    + "or both the ImageId and InstanceType parameters.";
    private static final String ACTIVE_INSTANCE_REFRESH_DESIRED_CONFIGURATION_MESSAGE =
            "An active instance refresh with a desired configuration exists. All configuration options derived from the desired configuration are not available for update while the instance refresh is active.";

    private static AutoScalingClient autoScaling;
    private static Ec2Client ec2;
    private static ElasticLoadBalancingV2Client elbV2;

    @BeforeAll
    static void setup() {
        autoScaling = TestFixtures.autoScalingClient();
        ec2 = TestFixtures.ec2Client();
        elbV2 = TestFixtures.elbV2Client();
    }

    @AfterAll
    static void cleanup() {
        if (autoScaling != null) {
            autoScaling.close();
        }
        if (ec2 != null) {
            ec2.close();
        }
        if (elbV2 != null) {
            elbV2.close();
        }
    }

    @Test
    @DisplayName("CreateAutoScalingGroup rejects launch templates without ImageId")
    void missingLaunchTemplateImageIdMapsToSdkAutoScalingException() {
        String launchTemplateName = TestFixtures.uniqueName("sdk-missing-image");
        String autoScalingGroupName = TestFixtures.uniqueName("sdk-missing-image-asg");

        ec2.createLaunchTemplate(CreateLaunchTemplateRequest.builder()
                .launchTemplateName(launchTemplateName)
                .launchTemplateData(RequestLaunchTemplateData.builder()
                        .instanceType("t3.micro")
                        .build())
                .build());

        assertThatThrownBy(() -> autoScaling.createAutoScalingGroup(CreateAutoScalingGroupRequest.builder()
                .autoScalingGroupName(autoScalingGroupName)
                .launchTemplate(LaunchTemplateSpecification.builder()
                        .launchTemplateName(launchTemplateName)
                        .version("1")
                        .build())
                .minSize(0)
                .maxSize(1)
                .desiredCapacity(1)
                .availabilityZones("us-east-1a")
                .build()))
                .isInstanceOfSatisfying(AutoScalingException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().serviceName()).isEqualTo("AutoScaling");
                    assertThat(error.awsErrorDetails().errorCode()).isEqualTo("ValidationError");
                    assertThat(error.awsErrorDetails().errorMessage())
                            .isEqualTo(MISSING_LAUNCH_TEMPLATE_IMAGE_ID_MESSAGE);
                    assertThat(error.requestId()).isNotBlank();
                    assertThat(error.getMessage()).contains(
                            MISSING_LAUNCH_TEMPLATE_IMAGE_ID_MESSAGE,
                            "Service: AutoScaling",
                            "Status Code: 400",
                            "Request ID: ",
                            "SDK Attempt Count: 1");
                });
    }

    @Test
    @DisplayName("CreateLaunchConfiguration rejects missing ImageId or InstanceType")
    void missingLaunchConfigurationImageIdMapsToSdkAutoScalingExceptionAtCreateTime() {
        String suffix = TestFixtures.uniqueName("sdk-lc");

        assertThatThrownBy(() -> autoScaling.createLaunchConfiguration(CreateLaunchConfigurationRequest.builder()
                .launchConfigurationName(suffix + "-missing-image")
                .instanceType("t3.micro")
                .build()))
                .isInstanceOfSatisfying(AutoScalingException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().serviceName()).isEqualTo("AutoScaling");
                    assertThat(error.awsErrorDetails().errorCode()).isEqualTo("ValidationError");
                    assertThat(error.awsErrorDetails().errorMessage())
                            .isEqualTo(INVALID_LAUNCH_CONFIGURATION_PARAMETERS_MESSAGE);
                    assertThat(error.requestId()).isNotBlank();
                    assertThat(error.getMessage()).contains(
                            INVALID_LAUNCH_CONFIGURATION_PARAMETERS_MESSAGE,
                            "Service: AutoScaling",
                            "Status Code: 400",
                            "Request ID: ",
                            "SDK Attempt Count: 1");
                });

        assertThatThrownBy(() -> autoScaling.createLaunchConfiguration(CreateLaunchConfigurationRequest.builder()
                .launchConfigurationName(suffix + "-missing-type")
                .imageId("ami-12345678")
                .build()))
                .isInstanceOfSatisfying(AutoScalingException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().serviceName()).isEqualTo("AutoScaling");
                    assertThat(error.awsErrorDetails().errorCode()).isEqualTo("ValidationError");
                    assertThat(error.awsErrorDetails().errorMessage())
                            .isEqualTo(INVALID_LAUNCH_CONFIGURATION_PARAMETERS_MESSAGE);
                });
    }

    @Test
    @DisplayName("UpdateAutoScalingGroup rejects desired configuration changes during active instance refresh")
    void activeInstanceRefreshDesiredConfigurationConflictMapsToSdkAutoScalingException() {
        String launchTemplateName = TestFixtures.uniqueName("sdk-active-refresh");
        String autoScalingGroupName = TestFixtures.uniqueName("sdk-active-refresh-asg");

        ec2.createLaunchTemplate(CreateLaunchTemplateRequest.builder()
                .launchTemplateName(launchTemplateName)
                .launchTemplateData(RequestLaunchTemplateData.builder()
                        .imageId("ami-12345678")
                        .instanceType("t3.micro")
                        .build())
                .build());
        ec2.createLaunchTemplateVersion(CreateLaunchTemplateVersionRequest.builder()
                .launchTemplateName(launchTemplateName)
                .sourceVersion("1")
                .launchTemplateData(RequestLaunchTemplateData.builder()
                        .imageId("ami-12345678")
                        .instanceType("t3.small")
                        .build())
                .build());
        ec2.createLaunchTemplateVersion(CreateLaunchTemplateVersionRequest.builder()
                .launchTemplateName(launchTemplateName)
                .sourceVersion("1")
                .launchTemplateData(RequestLaunchTemplateData.builder()
                        .imageId("ami-12345678")
                        .instanceType("t3.medium")
                        .build())
                .build());
        autoScaling.createAutoScalingGroup(CreateAutoScalingGroupRequest.builder()
                .autoScalingGroupName(autoScalingGroupName)
                .launchTemplate(LaunchTemplateSpecification.builder()
                        .launchTemplateName(launchTemplateName)
                        .version("1")
                        .build())
                .minSize(0)
                .maxSize(1)
                .desiredCapacity(1)
                .availabilityZones("us-east-1a")
                .build());
        autoScaling.attachInstances(AttachInstancesRequest.builder()
                .autoScalingGroupName(autoScalingGroupName)
                .instanceIds("i-sdk-active-refresh")
                .build());
        autoScaling.startInstanceRefresh(StartInstanceRefreshRequest.builder()
                .autoScalingGroupName(autoScalingGroupName)
                .desiredConfiguration(DesiredConfiguration.builder()
                        .launchTemplate(LaunchTemplateSpecification.builder()
                                .launchTemplateName(launchTemplateName)
                                .version("2")
                                .build())
                        .build())
                .build());

        assertThatThrownBy(() -> autoScaling.updateAutoScalingGroup(UpdateAutoScalingGroupRequest.builder()
                .autoScalingGroupName(autoScalingGroupName)
                .launchTemplate(LaunchTemplateSpecification.builder()
                        .launchTemplateName(launchTemplateName)
                        .version("3")
                        .build())
                .build()))
                .isInstanceOfSatisfying(AutoScalingException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().serviceName()).isEqualTo("AutoScaling");
                    assertThat(error.awsErrorDetails().errorCode()).isEqualTo("ValidationError");
                    assertThat(error.awsErrorDetails().errorMessage())
                            .isEqualTo(ACTIVE_INSTANCE_REFRESH_DESIRED_CONFIGURATION_MESSAGE);
                    assertThat(error.requestId()).isNotBlank();
                    assertThat(error.getMessage()).contains(
                            ACTIVE_INSTANCE_REFRESH_DESIRED_CONFIGURATION_MESSAGE,
                            "Service: AutoScaling",
                            "Status Code: 400",
                            "Request ID: ",
                            "SDK Attempt Count: 1");
                });
    }

    @Test
    @DisplayName("StartInstanceRefresh and DescribeInstanceRefreshes preserve SDK lifecycle state")
    void startAndDescribeInstanceRefreshLifecycle() {
        String launchTemplateName = TestFixtures.uniqueName("sdk-refresh-lifecycle");
        String autoScalingGroupName = TestFixtures.uniqueName("sdk-refresh-lifecycle-asg");
        boolean groupCreated = false;
        try {
            ec2.createLaunchTemplate(CreateLaunchTemplateRequest.builder()
                    .launchTemplateName(launchTemplateName)
                    .launchTemplateData(RequestLaunchTemplateData.builder()
                            .imageId("ami-12345678")
                            .instanceType("t3.micro")
                            .build())
                    .build());
            ec2.createLaunchTemplateVersion(CreateLaunchTemplateVersionRequest.builder()
                    .launchTemplateName(launchTemplateName)
                    .sourceVersion("1")
                    .launchTemplateData(RequestLaunchTemplateData.builder()
                            .imageId("ami-12345678")
                            .instanceType("t3.small")
                            .build())
                    .build());
            autoScaling.createAutoScalingGroup(CreateAutoScalingGroupRequest.builder()
                    .autoScalingGroupName(autoScalingGroupName)
                    .launchTemplate(LaunchTemplateSpecification.builder()
                            .launchTemplateName(launchTemplateName)
                            .version("1")
                            .build())
                    .minSize(1)
                    .maxSize(1)
                    .desiredCapacity(1)
                    .availabilityZones("us-east-1a")
                    .build());
            groupCreated = true;
            String originalInstanceId = awaitAutoScalingInstance(autoScalingGroupName);

            var started = autoScaling.startInstanceRefresh(StartInstanceRefreshRequest.builder()
                    .autoScalingGroupName(autoScalingGroupName)
                    .desiredConfiguration(DesiredConfiguration.builder()
                            .launchTemplate(LaunchTemplateSpecification.builder()
                                    .launchTemplateName(launchTemplateName)
                                    .version("2")
                                    .build())
                            .build())
                    .preferences(RefreshPreferences.builder()
                            .minHealthyPercentage(100)
                            .maxHealthyPercentage(100)
                            .skipMatching(true)
                            .build())
                    .build());
            var described = awaitInstanceRefresh(autoScalingGroupName, started.instanceRefreshId());

            var currentGroup = autoScaling.describeAutoScalingGroups(DescribeAutoScalingGroupsRequest.builder()
                    .autoScalingGroupNames(autoScalingGroupName)
                    .build()).autoScalingGroups().getFirst();

            assertThat(started.instanceRefreshId()).isNotBlank();
            assertThat(described.instanceRefreshId()).isEqualTo(started.instanceRefreshId());
            assertThat(described.statusAsString()).isEqualTo("Successful");
            assertThat(described.percentageComplete()).isEqualTo(100);
            assertThat(described.instancesToUpdate()).isZero();
            assertThat(described.desiredConfiguration().launchTemplate().version()).isEqualTo("2");
            assertThat(described.preferences().minHealthyPercentage()).isEqualTo(100);
            assertThat(described.preferences().maxHealthyPercentage()).isEqualTo(100);
            assertThat(currentGroup.instances()).hasSize(1);
            assertThat(currentGroup.instances().getFirst().instanceId()).isNotEqualTo(originalInstanceId);
            assertThat(currentGroup.launchTemplate().version()).isEqualTo("2");
        } finally {
            if (groupCreated) {
                autoScaling.deleteAutoScalingGroup(DeleteAutoScalingGroupRequest.builder()
                        .autoScalingGroupName(autoScalingGroupName)
                        .forceDelete(true)
                        .build());
            }
            try {
                ec2.deleteLaunchTemplate(DeleteLaunchTemplateRequest.builder()
                        .launchTemplateName(launchTemplateName)
                        .build());
            } catch (RuntimeException ignored) {
                // The primary assertions above retain any meaningful failure.
            }
        }
    }

    @Test
    @DisplayName("Reconciler restores a missing target at the target group's effective port")
    void reconcilerRestoresMissingTargetWithEffectivePort() throws InterruptedException {
        String launchTemplateName = TestFixtures.uniqueName("sdk-target-reconciliation-lt");
        String autoScalingGroupName = TestFixtures.uniqueName("sdk-target-reconciliation-asg");
        String targetGroupName = TestFixtures.uniqueName("sdk-target-reconciliation-tg");
        String instanceId = null;
        String targetGroupArn = null;
        boolean autoScalingGroupCreated = false;
        int targetPort = 18080;

        try {
            ec2.createLaunchTemplate(CreateLaunchTemplateRequest.builder()
                    .launchTemplateName(launchTemplateName)
                    .launchTemplateData(RequestLaunchTemplateData.builder()
                            .imageId("ami-0abcdef1234567890")
                            .instanceType("t3.micro")
                            .build())
                    .build());
            instanceId = ec2.runInstances(RunInstancesRequest.builder()
                            .imageId("ami-0abcdef1234567890")
                            .instanceType("t3.micro")
                            .minCount(1)
                            .maxCount(1)
                            .build())
                    .instances().get(0).instanceId();
            awaitRunningInstance(instanceId);

            targetGroupArn = elbV2.createTargetGroup(CreateTargetGroupRequest.builder()
                            .name(targetGroupName)
                            .protocol(ProtocolEnum.HTTP)
                            .port(targetPort)
                            .vpcId("vpc-sdk-target-reconciliation")
                            .targetType(TargetTypeEnum.INSTANCE)
                            .build())
                    .targetGroups().get(0).targetGroupArn();
            autoScaling.createAutoScalingGroup(CreateAutoScalingGroupRequest.builder()
                    .autoScalingGroupName(autoScalingGroupName)
                    .launchTemplate(LaunchTemplateSpecification.builder()
                            .launchTemplateName(launchTemplateName)
                            .version("1")
                            .build())
                    .minSize(0)
                    .maxSize(1)
                    .desiredCapacity(0)
                    .availabilityZones("us-east-1a")
                    .targetGroupARNs(targetGroupArn)
                    .build());
            autoScalingGroupCreated = true;
            autoScaling.attachInstances(AttachInstancesRequest.builder()
                    .autoScalingGroupName(autoScalingGroupName)
                    .instanceIds(instanceId)
                    .build());

            TargetHealthDescription initiallyReconciled =
                    awaitTargetRegistration(targetGroupArn, instanceId, targetPort);
            elbV2.deregisterTargets(DeregisterTargetsRequest.builder()
                    .targetGroupArn(targetGroupArn)
                    .targets(TargetDescription.builder().id(instanceId).port(targetPort).build())
                    .build());

            TargetHealthDescription healed = awaitTargetRegistration(targetGroupArn, instanceId, targetPort);

            assertThat(initiallyReconciled.target().id()).isEqualTo(instanceId);
            assertThat(initiallyReconciled.target().port()).isEqualTo(targetPort);
            assertThat(healed.target().id()).isEqualTo(instanceId);
            assertThat(healed.target().port()).isEqualTo(targetPort);
        } finally {
            if (autoScalingGroupCreated) {
                try {
                    autoScaling.deleteAutoScalingGroup(DeleteAutoScalingGroupRequest.builder()
                            .autoScalingGroupName(autoScalingGroupName)
                            .forceDelete(true)
                            .build());
                } catch (RuntimeException e) {
                    LOG.log(System.Logger.Level.WARNING,
                            "Could not clean up Auto Scaling group " + autoScalingGroupName, e);
                }
            }
            if (instanceId != null) {
                try {
                    ec2.terminateInstances(TerminateInstancesRequest.builder().instanceIds(instanceId).build());
                } catch (RuntimeException e) {
                    LOG.log(System.Logger.Level.WARNING, "Could not clean up EC2 instance " + instanceId, e);
                }
            }
            if (targetGroupArn != null) {
                try {
                    elbV2.deleteTargetGroup(DeleteTargetGroupRequest.builder()
                            .targetGroupArn(targetGroupArn)
                            .build());
                } catch (RuntimeException e) {
                    LOG.log(System.Logger.Level.WARNING, "Could not clean up target group " + targetGroupArn, e);
                }
            }
            try {
                ec2.deleteLaunchTemplate(DeleteLaunchTemplateRequest.builder()
                        .launchTemplateName(launchTemplateName)
                        .build());
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.WARNING,
                        "Could not clean up launch template " + launchTemplateName, e);
            }
        }
    }

    private static void awaitRunningInstance(String instanceId) throws InterruptedException {
        for (int attempt = 0; attempt < 60; attempt++) {
            var response = ec2.describeInstances(DescribeInstancesRequest.builder().instanceIds(instanceId).build());
            if (!response.reservations().isEmpty()
                    && !response.reservations().get(0).instances().isEmpty()
                    && response.reservations().get(0).instances().get(0).state().name() == InstanceStateName.RUNNING) {
                return;
            }
            Thread.sleep(500);
        }
        throw new AssertionError("EC2 instance did not become running: " + instanceId);
    }

    private static String awaitAutoScalingInstance(String autoScalingGroupName) {
        for (int attempt = 0; attempt < 60; attempt++) {
            var response = autoScaling.describeAutoScalingGroups(DescribeAutoScalingGroupsRequest.builder()
                    .autoScalingGroupNames(autoScalingGroupName)
                    .build());
            if (!response.autoScalingGroups().isEmpty()
                    && !response.autoScalingGroups().getFirst().instances().isEmpty()) {
                return response.autoScalingGroups().getFirst().instances().getFirst().instanceId();
            }
            sleepForReconcile();
        }
        throw new AssertionError("Auto Scaling instance did not appear for " + autoScalingGroupName);
    }

    private static software.amazon.awssdk.services.autoscaling.model.InstanceRefresh awaitInstanceRefresh(
            String autoScalingGroupName,
            String instanceRefreshId) {
        for (int attempt = 0; attempt < 120; attempt++) {
            var refresh = autoScaling.describeInstanceRefreshes(DescribeInstanceRefreshesRequest.builder()
                    .autoScalingGroupName(autoScalingGroupName)
                    .instanceRefreshIds(instanceRefreshId)
                    .build()).instanceRefreshes().getFirst();
            if (!"Pending".equals(refresh.statusAsString()) && !"InProgress".equals(refresh.statusAsString())) {
                return refresh;
            }
            sleepForReconcile();
        }
        throw new AssertionError("Instance refresh did not reach a terminal state: " + instanceRefreshId);
    }

    private static void sleepForReconcile() {
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Interrupted while waiting for Auto Scaling reconciliation", e);
        }
    }

    private static TargetHealthDescription awaitTargetRegistration(
            String targetGroupArn,
            String instanceId,
            int port) throws InterruptedException {
        for (int attempt = 0; attempt < 60; attempt++) {
            var response = elbV2.describeTargetHealth(DescribeTargetHealthRequest.builder()
                    .targetGroupArn(targetGroupArn)
                    .build());
            var registration = response.targetHealthDescriptions().stream()
                    .filter(health -> instanceId.equals(health.target().id()))
                    .filter(health -> Integer.valueOf(port).equals(health.target().port()))
                    .findFirst();
            if (registration.isPresent()) {
                return registration.get();
            }
            Thread.sleep(500);
        }
        throw new AssertionError(
                "Target registration did not appear for " + instanceId + " on port " + port);
    }
}
