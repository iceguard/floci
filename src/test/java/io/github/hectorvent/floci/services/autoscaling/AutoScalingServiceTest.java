package io.github.hectorvent.floci.services.autoscaling;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.PersistentStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.services.autoscaling.model.AsgInstance;
import io.github.hectorvent.floci.services.autoscaling.model.InstanceRefresh;
import io.github.hectorvent.floci.services.autoscaling.model.LaunchConfiguration;
import io.github.hectorvent.floci.services.autoscaling.model.MixedInstancesPolicy;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.Ec2UserData;
import io.github.hectorvent.floci.services.ec2.model.GroupIdentifier;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.LaunchTemplate;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AutoScalingServiceTest {

    private static final String REGION = "us-east-1";
    private AutoScalingService service;

    @BeforeEach
    void setUp() {
        service = new AutoScalingService();
        service.regionResolver = new RegionResolver(REGION, "000000000000");
        service.createAutoScalingGroup(REGION,
                "test-asg",
                null,
                "lt-original",
                null,
                "1",
                null,
                0,
                3,
                1,
                300,
                List.of("us-east-1a"),
                List.of("subnet-12345678"),
                List.of(),
                List.of(),
                "EC2",
                0,
                List.of("Default"),
                java.util.Map.of(), java.util.Map.of());
    }

    @Test
    void startInstanceRefreshStoresCompletedRefreshAndAppliesDesiredLaunchTemplate() {
        InstanceRefresh request = new InstanceRefresh();
        request.setStrategy("Rolling");
        request.setDesiredLaunchTemplateId("lt-updated");
        request.setDesiredLaunchTemplateVersion("2");
        request.setMinHealthyPercentage(90);
        request.setMaxHealthyPercentage(120);
        request.setInstanceWarmup(200);
        request.setSkipMatching(true);
        request.setAutoRollback(false);

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "test-asg", request);

        assertNotNull(refresh.getInstanceRefreshId());
        assertEquals("test-asg", refresh.getAutoScalingGroupName());
        assertEquals("Rolling", refresh.getStrategy());
        assertEquals("Successful", refresh.getStatus());
        assertEquals(100, refresh.getPercentageComplete());
        assertEquals(0, refresh.getInstancesToUpdate());
        assertEquals("lt-updated", refresh.getDesiredLaunchTemplateId());
        assertEquals("2", refresh.getDesiredLaunchTemplateVersion());
        assertEquals(90, refresh.getMinHealthyPercentage());
        assertEquals(120, refresh.getMaxHealthyPercentage());
        assertEquals(200, refresh.getInstanceWarmup());
        assertEquals(Boolean.TRUE, refresh.getSkipMatching());
        assertEquals(Boolean.FALSE, refresh.getAutoRollback());
        assertEquals(List.of(), refresh.getCheckpointPercentages());

        AutoScalingService.InstanceRefreshPage page =
                service.describeInstanceRefreshes(REGION, "test-asg", List.of(refresh.getInstanceRefreshId()), null, null);
        assertEquals(1, page.instanceRefreshes().size());
        assertEquals(refresh.getInstanceRefreshId(), page.instanceRefreshes().getFirst().getInstanceRefreshId());
        assertNull(page.nextToken());

        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        assertEquals("lt-updated", group.getLaunchTemplateId());
        assertEquals("2", group.getLaunchTemplateVersion());
        assertNull(group.getLaunchConfigurationName());
    }

    @Test
    void deletePolicyIsScopedToRegionAndAutoScalingGroup() {
        service.createAutoScalingGroup(REGION,
                "other-asg", null, "lt-original", null, "1", null,
                0, 3, 1, 300, List.of("us-east-1a"), List.of("subnet-12345678"),
                List.of(), List.of(), "EC2", 0, List.of("Default"),
                java.util.Map.of(), java.util.Map.of());
        service.createAutoScalingGroup("us-west-2",
                "test-asg", null, "lt-original", null, "1", null,
                0, 3, 1, 300, List.of("us-west-2a"), List.of("subnet-12345678"),
                List.of(), List.of(), "EC2", 0, List.of("Default"),
                java.util.Map.of(), java.util.Map.of());
        service.putScalingPolicy(REGION, "test-asg", "shared-name", null, null,
                1, 0, null, null);
        service.putScalingPolicy(REGION, "other-asg", "shared-name", null, null,
                1, 0, null, null);
        service.putScalingPolicy("us-west-2", "test-asg", "shared-name", null, null,
                1, 0, null, null);

        service.deletePolicy(REGION, "test-asg", "shared-name");

        assertTrue(service.describePolicies(REGION, "test-asg", List.of("shared-name")).isEmpty());
        assertEquals(1, service.describePolicies(REGION, "other-asg", List.of("shared-name")).size());
        assertEquals(1, service.describePolicies("us-west-2", "test-asg", List.of("shared-name")).size());
    }

    @Test
    void createAutoScalingGroupRejectsResolvedLaunchTemplateWithoutImageId() {
        Ec2Service ec2Service = mock(Ec2Service.class);
        service.ec2Service = ec2Service;
        LaunchTemplate version = new LaunchTemplate();
        version.setImageId(null);
        when(ec2Service.describeLaunchTemplateVersions(REGION, "lt-no-image", null, List.of("1")))
                .thenReturn(List.of(version));

        AwsException error = assertThrows(AwsException.class, () -> service.createAutoScalingGroup(REGION,
                "missing-image-asg",
                null,
                "lt-no-image",
                null,
                "1",
                null,
                0,
                1,
                1,
                300,
                List.of("us-east-1a"),
                List.of(),
                List.of(),
                List.of(),
                "EC2",
                0,
                List.of("Default"),
                java.util.Map.of(), java.util.Map.of()));

        assertEquals("ValidationError", error.getErrorCode());
        assertEquals(AutoScalingService.MISSING_LAUNCH_TEMPLATE_IMAGE_ID_MESSAGE, error.getMessage());
        assertEquals(400, error.getHttpStatus());
        assertTrue(service.describeAutoScalingGroups(REGION, List.of("missing-image-asg")).isEmpty());
    }

    @Test
    void createLaunchConfigurationRejectsMissingImageOrInstanceTypeWithoutInstanceId() {
        AwsException missingImage = assertThrows(AwsException.class, () -> service.createLaunchConfiguration(REGION,
                "lc-no-image",
                null,
                "",
                "t3.micro",
                null,
                List.of(),
                null,
                null,
                false));

        assertEquals("ValidationError", missingImage.getErrorCode());
        assertEquals(AutoScalingService.INVALID_LAUNCH_CONFIGURATION_PARAMETERS_MESSAGE, missingImage.getMessage());
        assertEquals(400, missingImage.getHttpStatus());
        assertTrue(service.describeLaunchConfigurations(REGION, List.of("lc-no-image")).isEmpty());

        AwsException missingInstanceType = assertThrows(AwsException.class,
                () -> service.createLaunchConfiguration(REGION,
                        "lc-no-instance-type",
                        null,
                        "ami-12345678",
                        null,
                        null,
                        List.of(),
                        null,
                        null,
                        false));

        assertEquals("ValidationError", missingInstanceType.getErrorCode());
        assertEquals(AutoScalingService.INVALID_LAUNCH_CONFIGURATION_PARAMETERS_MESSAGE,
                missingInstanceType.getMessage());
        assertEquals(400, missingInstanceType.getHttpStatus());
        assertTrue(service.describeLaunchConfigurations(REGION, List.of("lc-no-instance-type")).isEmpty());
    }

    @Test
    void createLaunchConfigurationWithInstanceIdCopiesSourceInstanceLaunchAttributes() {
        Ec2Service ec2Service = mock(Ec2Service.class);
        service.ec2Service = ec2Service;
        Instance source = new Instance();
        source.setInstanceId("i-1234567890abcdef0");
        source.setImageId("ami-from-instance");
        source.setInstanceType("m7g.large");
        source.setKeyName("source-key");
        source.setSecurityGroups(List.of(new GroupIdentifier("sg-source", "default")));
        source.setEncodedUserData("/wAJ");
        source.setIamInstanceProfileArn("arn:aws:iam::000000000000:instance-profile/source");
        Reservation reservation = new Reservation();
        reservation.getInstances().add(source);
        when(ec2Service.describeInstances(REGION, List.of("i-1234567890abcdef0"), java.util.Map.of()))
                .thenReturn(List.of(reservation));

        var launchConfiguration = service.createLaunchConfiguration(REGION,
                "lc-from-instance",
                "i-1234567890abcdef0",
                null,
                null,
                null,
                List.of(),
                null,
                null,
                false);

        assertEquals("ami-from-instance", launchConfiguration.getImageId());
        assertEquals("m7g.large", launchConfiguration.getInstanceType());
        assertEquals("source-key", launchConfiguration.getKeyName());
        assertEquals(List.of("sg-source"), launchConfiguration.getSecurityGroups());
        assertEquals("/wAJ", launchConfiguration.getUserData());
        assertEquals("arn:aws:iam::000000000000:instance-profile/source",
                launchConfiguration.getIamInstanceProfile());
        assertEquals(launchConfiguration,
                service.describeLaunchConfigurations(REGION, List.of("lc-from-instance")).getFirst());
    }

    @Test
    void launchConfigurationValidatesAndPreservesPresentEmptyUserData() {
        var launchConfiguration = service.createLaunchConfiguration(REGION,
                "lc-empty-user-data", null, "ami-12345678", "t3.micro", null,
                List.of(), "", null, false);

        assertEquals("", launchConfiguration.getUserData());

        String oversized = java.util.Base64.getEncoder().encodeToString(
                new byte[Ec2UserData.MAX_DECODED_BYTES + 1]);
        AwsException error = assertThrows(AwsException.class, () -> service.createLaunchConfiguration(REGION,
                "lc-oversized-user-data", null, "ami-12345678", "t3.micro", null,
                List.of(), oversized, null, false));
        assertEquals("InvalidParameterValue", error.getErrorCode());
        assertEquals("User data is limited to 16384 bytes", error.getMessage());
    }

    @Test
    void launchConfigurationExactUserDataSurvivesPersistence(@TempDir Path dir) {
        Path file = dir.resolve("autoscaling-launch-configurations.json");
        TypeReference<Map<String, LaunchConfiguration>> type = new TypeReference<>() {};
        LaunchConfiguration launchConfiguration = new LaunchConfiguration();
        launchConfiguration.setLaunchConfigurationName("lc-binary-user-data");
        launchConfiguration.setUserData("/wAJ");

        StorageBackend<String, LaunchConfiguration> first = new PersistentStorage<>(file, type);
        first.put("us-east-1::lc-binary-user-data", launchConfiguration);

        StorageBackend<String, LaunchConfiguration> restarted = new PersistentStorage<>(file, type);
        restarted.load();
        assertEquals("/wAJ", restarted.get("us-east-1::lc-binary-user-data")
                .orElseThrow()
                .getUserData());
    }

    @Test
    void createAutoScalingGroupRejectsUnresolvedLaunchTemplateBeforeMutation() {
        Ec2Service ec2Service = mock(Ec2Service.class);
        service.ec2Service = ec2Service;
        when(ec2Service.describeLaunchTemplateVersions(REGION, "lt-missing", null, List.of("1")))
                .thenReturn(List.of());

        AwsException error = assertThrows(AwsException.class, () -> service.createAutoScalingGroup(REGION,
                "missing-template-asg",
                null,
                "lt-missing",
                null,
                "1",
                null,
                0,
                1,
                1,
                300,
                List.of("us-east-1a"),
                List.of(),
                List.of(),
                List.of(),
                "EC2",
                0,
                List.of("Default"),
                java.util.Map.of(), java.util.Map.of()));

        assertEquals("ValidationError", error.getErrorCode());
        assertEquals(AutoScalingService.INVALID_LAUNCH_TEMPLATE_MESSAGE, error.getMessage());
        assertEquals(400, error.getHttpStatus());
        assertTrue(service.describeAutoScalingGroups(REGION, List.of("missing-template-asg")).isEmpty());
    }

    @Test
    void updateAutoScalingGroupRejectsResolvedLaunchTemplateWithoutImageIdBeforeMutation() {
        Ec2Service ec2Service = mock(Ec2Service.class);
        service.ec2Service = ec2Service;
        LaunchTemplate version = new LaunchTemplate();
        version.setImageId("");
        when(ec2Service.describeLaunchTemplateVersions(REGION, "lt-no-image", null, List.of("2")))
                .thenReturn(List.of(version));

        AwsException error = assertThrows(AwsException.class, () -> service.updateAutoScalingGroup(
                REGION,
                "test-asg",
                null,
                "lt-no-image",
                null,
                "2",
                null,
                null,
                5,
                null,
                null,
                null,
                null,
                null,
                null,
                null));

        assertEquals("ValidationError", error.getErrorCode());
        assertEquals(AutoScalingService.MISSING_LAUNCH_TEMPLATE_IMAGE_ID_MESSAGE, error.getMessage());
        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        assertEquals("lt-original", group.getLaunchTemplateId());
        assertEquals(3, group.getMaxSize());
    }

    @Test
    void updateAutoScalingGroupRejectsVersionWithoutLaunchTemplateIdentifier() {
        AwsException error = assertThrows(AwsException.class, () -> service.updateAutoScalingGroup(
                REGION,
                "test-asg",
                null,
                null,
                null,
                "2",
                null,
                null,
                5,
                null,
                null,
                null,
                null,
                null,
                null,
                null));

        assertEquals("ValidationError", error.getErrorCode());
        assertEquals("LaunchTemplateVersion requires a LaunchTemplateId or LaunchTemplateName.", error.getMessage());
        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        assertEquals("1", group.getLaunchTemplateVersion());
        assertEquals(3, group.getMaxSize());
    }

    @Test
    void updateAutoScalingGroupRejectsDesiredConfigurationChangeDuringActiveInstanceRefresh() {
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-original", "InService", "lt-original", "1");
        InstanceRefresh request = new InstanceRefresh();
        request.setDesiredLaunchTemplateId("lt-refresh");
        request.setDesiredLaunchTemplateVersion("2");
        service.startInstanceRefresh(REGION, "test-asg", request);

        AwsException error = assertThrows(AwsException.class, () -> service.updateAutoScalingGroup(
                REGION,
                "test-asg",
                null,
                "lt-next",
                null,
                "3",
                null,
                null,
                5,
                null,
                null,
                null,
                null,
                null,
                null,
                null));

        assertEquals("ValidationError", error.getErrorCode());
        assertEquals(AutoScalingService.ACTIVE_INSTANCE_REFRESH_DESIRED_CONFIGURATION_MESSAGE, error.getMessage());
        assertEquals(400, error.getHttpStatus());
        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        assertEquals("lt-original", group.getLaunchTemplateId());
        assertEquals("1", group.getLaunchTemplateVersion());
        assertEquals(3, group.getMaxSize());
    }

    @Test
    void describeInstanceRefreshesPaginatesNewestFirst() {
        InstanceRefresh first = service.startInstanceRefresh(REGION, "test-asg", new InstanceRefresh());
        InstanceRefresh second = service.startInstanceRefresh(REGION, "test-asg", new InstanceRefresh());

        AutoScalingService.InstanceRefreshPage firstPage =
                service.describeInstanceRefreshes(REGION, "test-asg", List.of(), 1, null);
        assertEquals(1, firstPage.instanceRefreshes().size());
        assertEquals(second.getInstanceRefreshId(), firstPage.instanceRefreshes().getFirst().getInstanceRefreshId());
        assertEquals("1", firstPage.nextToken());

        AutoScalingService.InstanceRefreshPage secondPage =
                service.describeInstanceRefreshes(REGION, "test-asg", List.of(), 1, firstPage.nextToken());
        assertEquals(1, secondPage.instanceRefreshes().size());
        assertEquals(first.getInstanceRefreshId(), secondPage.instanceRefreshes().getFirst().getInstanceRefreshId());
        assertNull(secondPage.nextToken());
    }

    @Test
    void startInstanceRefreshSnapshotsCandidatesWithoutDrainingTheGroup() {
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-original", "InService", "lt-original", "1");

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "test-asg", new InstanceRefresh());

        assertEquals("InProgress", refresh.getStatus());
        assertEquals("Instance refresh in progress.", refresh.getStatusReason());
        assertEquals(0, refresh.getPercentageComplete());
        assertEquals(1, refresh.getInstancesToUpdate());
        assertEquals(List.of("i-original"), refresh.getCandidateInstanceIds());
        assertEquals("i-original", refresh.getReplacements().getFirst().getOriginalInstanceId());
        assertEquals("Pending", refresh.getReplacements().getFirst().getPhase());
        assertNull(refresh.getEndTime());

        AsgInstance instance = service.describeAutoScalingGroups(REGION, List.of("test-asg"))
                .getFirst()
                .getInstances()
                .getFirst();
        assertEquals("InService", instance.getLifecycleState());
    }

    @Test
    void startInstanceRefreshRejectsSecondRefreshWhileFirstIsActive() {
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-original", "InService", "lt-original", "1");
        service.startInstanceRefresh(REGION, "test-asg", new InstanceRefresh());

        AwsException error = assertThrows(AwsException.class,
                () -> service.startInstanceRefresh(REGION, "test-asg", new InstanceRefresh()));

        assertEquals("InstanceRefreshInProgress", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
    }

    @Test
    void concurrentStartsCreateExactlyOneActiveRefresh() throws Exception {
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-original", "InService", "lt-original", "1");
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<Object> first = executor.submit(() -> startRefreshAfterBarrier(ready, start));
            Future<Object> second = executor.submit(() -> startRefreshAfterBarrier(ready, start));
            ready.await();
            start.countDown();

            List<Object> results = List.of(first.get(), second.get());
            assertEquals(1, results.stream().filter(InstanceRefresh.class::isInstance).count());
            assertEquals(1, results.stream()
                    .filter(AwsException.class::isInstance)
                    .map(AwsException.class::cast)
                    .filter(error -> "InstanceRefreshInProgress".equals(error.getErrorCode()))
                    .count());
            assertEquals(1, service.describeInstanceRefreshes(REGION, "test-asg", List.of(), null, null)
                    .instanceRefreshes().stream()
                    .filter(refresh -> "InProgress".equals(refresh.getStatus()))
                    .count());
        }
    }

    @Test
    void mixedOverrideChangeIsNotSkipped() {
        MixedInstancesPolicy source = mixedInstancesPolicy("lt-mixed", "1", "t3.small");
        createWithMixedInstancesPolicy("mixed-refresh", source);
        AutoScalingGroupFixture.addInstance(service, REGION, "mixed-refresh", "i-original",
                "InService", "lt-mixed", "1", "t3.small");
        InstanceRefresh request = new InstanceRefresh();
        request.setSkipMatching(true);
        request.setDesiredMixedInstancesPolicy(mixedInstancesPolicy("lt-mixed", "1", "t3.medium"));

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "mixed-refresh", request);

        assertEquals(List.of("i-original"), refresh.getCandidateInstanceIds());
        assertEquals("t3.small", source.getLaunchTemplate().getOverrides().getFirst().getInstanceType());
    }

    @Test
    void rejectsInvalidHealthyPercentageRange() {
        InstanceRefresh request = new InstanceRefresh();
        request.setMinHealthyPercentage(101);
        request.setMaxHealthyPercentage(100);

        AwsException error = assertThrows(AwsException.class,
                () -> service.startInstanceRefresh(REGION, "test-asg", request));

        assertEquals("ValidationError", error.getErrorCode());
    }

    @Test
    void autoRollbackCapturesActualMemberIdentityWhenGroupPointerAlreadyMoved() {
        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        group.setLaunchTemplateVersion("2");
        AutoScalingGroupFixture.addInstance(
                service, REGION, "test-asg", "i-original", "InService", "lt-original", "1", "t3.micro");
        InstanceRefresh request = new InstanceRefresh();
        request.setAutoRollback(true);
        request.setDesiredLaunchTemplateId("lt-original");
        request.setDesiredLaunchTemplateVersion("2");

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "test-asg", request);

        assertEquals("InProgress", refresh.getStatus());
        assertEquals(Boolean.TRUE, refresh.getAutoRollback());
        assertEquals("lt-original", refresh.getSourceLaunchTemplateId());
        assertEquals("1", refresh.getSourceLaunchTemplateVersion());
        assertEquals("1", refresh.getReplacements().getFirst().getOriginalLaunchTemplateVersion());
        assertEquals("t3.micro", refresh.getReplacements().getFirst().getOriginalInstanceType());
    }

    @Test
    void autoRollbackPreservesMixedPolicyWhileRestoringActualMemberVersion() {
        MixedInstancesPolicy policy = mixedInstancesPolicy("lt-mixed", "2", "t3.small");
        MixedInstancesPolicy.InstancesDistribution distribution =
                new MixedInstancesPolicy.InstancesDistribution();
        distribution.setOnDemandBaseCapacity(1);
        distribution.setOnDemandPercentageAboveBaseCapacity(25);
        distribution.setSpotAllocationStrategy("capacity-optimized");
        policy.setInstancesDistribution(distribution);
        createWithMixedInstancesPolicy("mixed-rollback", policy);
        AutoScalingGroupFixture.addInstance(service, REGION, "mixed-rollback", "i-original",
                "InService", "lt-mixed", "1", "t3.small");
        InstanceRefresh request = new InstanceRefresh();
        request.setAutoRollback(true);

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "mixed-rollback", request);

        MixedInstancesPolicy sourcePolicy = refresh.getSourceMixedInstancesPolicy();
        assertNotNull(sourcePolicy);
        assertEquals("1", sourcePolicy.getLaunchTemplate().getLaunchTemplateSpecification().getVersion());
        assertEquals("t3.small", sourcePolicy.getLaunchTemplate().getOverrides().getFirst().getInstanceType());
        assertEquals(25, sourcePolicy.getInstancesDistribution().getOnDemandPercentageAboveBaseCapacity());

        var group = service.describeAutoScalingGroups(REGION, List.of("mixed-rollback")).getFirst();
        AutoScalingService.restoreSourceConfiguration(group, refresh);
        assertEquals("1", group.getMixedInstancesPolicy().getLaunchTemplate()
                .getLaunchTemplateSpecification().getVersion());
        assertEquals("t3.small", group.getMixedInstancesPolicy().getLaunchTemplate()
                .getOverrides().getFirst().getInstanceType());
        assertEquals("capacity-optimized",
                group.getMixedInstancesPolicy().getInstancesDistribution().getSpotAllocationStrategy());
    }

    @Test
    void startInstanceRefreshSkipMatchingLeavesMatchingInstancesInService() {
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-matching", "InService", "lt-original", "1");
        InstanceRefresh request = new InstanceRefresh();
        request.setSkipMatching(true);

        service.startInstanceRefresh(REGION, "test-asg", request);

        AsgInstance instance = service.describeAutoScalingGroups(REGION, List.of("test-asg"))
                .getFirst()
                .getInstances()
                .getFirst();
        assertEquals("InService", instance.getLifecycleState());
    }

    @Test
    void startInstanceRefreshWithLaunchTemplateAliasDoesNotSkipExistingInstances() {
        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        group.setLaunchTemplateVersion("$Latest");
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-original", "InService", "lt-original", "1");
        InstanceRefresh request = new InstanceRefresh();
        request.setSkipMatching(true);

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "test-asg", request);

        assertEquals("InProgress", refresh.getStatus());
        assertEquals(1, refresh.getInstancesToUpdate());
        assertEquals("InService", group.getInstances().getFirst().getLifecycleState());
    }

    @Test
    void startInstanceRefreshWithDefaultLaunchTemplateAliasDoesNotSkipExistingInstances() {
        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        group.setLaunchTemplateVersion("$Default");
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-original", "InService", "lt-original", "1");
        InstanceRefresh request = new InstanceRefresh();
        request.setSkipMatching(true);

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "test-asg", request);

        assertEquals("InProgress", refresh.getStatus());
        assertEquals(1, refresh.getInstancesToUpdate());
        assertEquals("InService", group.getInstances().getFirst().getLifecycleState());
    }

    @Test
    void startInstanceRefreshWithDefaultLaunchTemplateVersionDoesNotSkipExistingInstances() {
        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        group.setLaunchTemplateVersion(null);
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-original", "InService", "lt-original", "1");
        InstanceRefresh request = new InstanceRefresh();
        request.setSkipMatching(true);

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "test-asg", request);

        assertEquals("InProgress", refresh.getStatus());
        assertEquals(1, refresh.getInstancesToUpdate());
        assertEquals("InService", group.getInstances().getFirst().getLifecycleState());
    }

    @Test
    void startInstanceRefreshWithBlankLaunchTemplateVersionDoesNotSkipExistingInstances() {
        var group = service.describeAutoScalingGroups(REGION, List.of("test-asg")).getFirst();
        group.setLaunchTemplateVersion("");
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-original", "InService", "lt-original", "1");
        InstanceRefresh request = new InstanceRefresh();
        request.setSkipMatching(true);

        InstanceRefresh refresh = service.startInstanceRefresh(REGION, "test-asg", request);

        assertEquals("InProgress", refresh.getStatus());
        assertEquals(1, refresh.getInstancesToUpdate());
        assertEquals("InService", group.getInstances().getFirst().getLifecycleState());
    }

    @Test
    void deleteAutoScalingGroupWithoutForceRejectsActiveInstances() {
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-active", "InService", "lt-original", "1");

        AwsException error = assertThrows(AwsException.class,
                () -> service.deleteAutoScalingGroup(REGION, "test-asg", false));

        assertEquals("ResourceInUse", error.getErrorCode());
    }

    @Test
    void forceDeleteAutoScalingGroupTerminatesActiveEc2Instances() {
        Ec2Service ec2Service = mock(Ec2Service.class);
        service.ec2Service = ec2Service;
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-active", "InService", "lt-original", "1");
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-terminated", "Terminated", "lt-original", "1");

        service.deleteAutoScalingGroup(REGION, "test-asg", true);

        verify(ec2Service).terminateInstances(REGION, List.of("i-active"));
        assertTrue(service.describeAutoScalingGroups(REGION, List.of("test-asg")).isEmpty());
    }

    @Test
    void forceDeleteAutoScalingGroupIgnoresStaleEc2Membership() {
        Ec2Service ec2Service = mock(Ec2Service.class);
        service.ec2Service = ec2Service;
        AutoScalingGroupFixture.addInstance(service, REGION, "test-asg", "i-stale", "InService", "lt-original", "1");
        doThrow(new AwsException("InvalidInstanceID.NotFound", "Instance i-stale was not found.", 400))
                .when(ec2Service)
                .terminateInstances(REGION, List.of("i-stale"));

        service.deleteAutoScalingGroup(REGION, "test-asg", true);

        verify(ec2Service).terminateInstances(REGION, List.of("i-stale"));
        assertTrue(service.describeAutoScalingGroups(REGION, List.of("test-asg")).isEmpty());
    }

    @Test
    void createAutoScalingGroupRejectsMixedInstancesPolicyWithoutLaunchTemplate() {
        MixedInstancesPolicy policy = new MixedInstancesPolicy();
        MixedInstancesPolicy.InstancesDistribution distribution =
                new MixedInstancesPolicy.InstancesDistribution();
        distribution.setOnDemandBaseCapacity(1);
        policy.setInstancesDistribution(distribution);

        AwsException error = assertThrows(AwsException.class,
                () -> createWithMixedInstancesPolicy("mixed-no-lt", policy));

        assertEquals("ValidationError", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
    }

    @Test
    void createAutoScalingGroupRejectsMixedInstancesPolicyWithBlankLaunchTemplateIdentifiers() {
        MixedInstancesPolicy policy = new MixedInstancesPolicy();
        MixedInstancesPolicy.LaunchTemplate launchTemplate = new MixedInstancesPolicy.LaunchTemplate();
        MixedInstancesPolicy.LaunchTemplateSpecification specification =
                new MixedInstancesPolicy.LaunchTemplateSpecification();
        specification.setLaunchTemplateId("");
        specification.setLaunchTemplateName("  ");
        launchTemplate.setLaunchTemplateSpecification(specification);
        policy.setLaunchTemplate(launchTemplate);

        AwsException error = assertThrows(AwsException.class,
                () -> createWithMixedInstancesPolicy("mixed-blank-lt", policy));

        assertEquals("ValidationError", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
    }

    @Test
    void createAutoScalingGroupAcceptsMixedInstancesPolicyWithLaunchTemplate() {
        MixedInstancesPolicy policy = new MixedInstancesPolicy();
        MixedInstancesPolicy.LaunchTemplate launchTemplate = new MixedInstancesPolicy.LaunchTemplate();
        MixedInstancesPolicy.LaunchTemplateSpecification specification =
                new MixedInstancesPolicy.LaunchTemplateSpecification();
        specification.setLaunchTemplateId("lt-mixed");
        launchTemplate.setLaunchTemplateSpecification(specification);
        policy.setLaunchTemplate(launchTemplate);

        createWithMixedInstancesPolicy("mixed-with-lt", policy);

        var group = service.describeAutoScalingGroups(REGION, List.of("mixed-with-lt")).getFirst();
        assertEquals("lt-mixed",
                group.getMixedInstancesPolicy().getLaunchTemplate()
                        .getLaunchTemplateSpecification().getLaunchTemplateId());
    }

    private void createWithMixedInstancesPolicy(String name, MixedInstancesPolicy policy) {
        service.createAutoScalingGroup(REGION,
                name,
                null,
                null,
                null,
                null,
                policy,
                0,
                3,
                1,
                300,
                List.of("us-east-1a"),
                List.of(),
                List.of(),
                List.of(),
                "EC2",
                0,
                List.of("Default"),
                java.util.Map.of(), java.util.Map.of());
    }

    private Object startRefreshAfterBarrier(CountDownLatch ready, CountDownLatch start) throws InterruptedException {
        ready.countDown();
        start.await();
        try {
            return service.startInstanceRefresh(REGION, "test-asg", new InstanceRefresh());
        } catch (AwsException error) {
            return error;
        }
    }

    private static MixedInstancesPolicy mixedInstancesPolicy(String launchTemplateId, String version,
                                                              String instanceType) {
        MixedInstancesPolicy policy = new MixedInstancesPolicy();
        MixedInstancesPolicy.LaunchTemplate launchTemplate = new MixedInstancesPolicy.LaunchTemplate();
        MixedInstancesPolicy.LaunchTemplateSpecification specification =
                new MixedInstancesPolicy.LaunchTemplateSpecification();
        specification.setLaunchTemplateId(launchTemplateId);
        specification.setVersion(version);
        launchTemplate.setLaunchTemplateSpecification(specification);
        MixedInstancesPolicy.LaunchTemplateOverride override =
                new MixedInstancesPolicy.LaunchTemplateOverride();
        override.setInstanceType(instanceType);
        launchTemplate.setOverrides(List.of(override));
        policy.setLaunchTemplate(launchTemplate);
        return policy;
    }

    private static final class AutoScalingGroupFixture {
        private static void addInstance(AutoScalingService service, String region, String name, String instanceId,
                String lifecycleState, String launchTemplateId, String launchTemplateVersion) {
            addInstance(service, region, name, instanceId, lifecycleState,
                    launchTemplateId, launchTemplateVersion, null);
        }

        private static void addInstance(AutoScalingService service, String region, String name, String instanceId,
                String lifecycleState, String launchTemplateId, String launchTemplateVersion, String instanceType) {
            AsgInstance instance = new AsgInstance();
            instance.setInstanceId(instanceId);
            instance.setLifecycleState(lifecycleState);
            instance.setHealthStatus("Healthy");
            instance.setLaunchTemplateId(launchTemplateId);
            instance.setLaunchTemplateVersion(launchTemplateVersion);
            instance.setInstanceType(instanceType);
            service.describeAutoScalingGroups(region, List.of(name))
                    .getFirst()
                    .getInstances()
                    .add(instance);
        }
    }
}
