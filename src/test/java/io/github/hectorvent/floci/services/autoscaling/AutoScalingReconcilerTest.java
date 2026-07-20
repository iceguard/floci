package io.github.hectorvent.floci.services.autoscaling;

import io.github.hectorvent.floci.services.autoscaling.model.AsgInstance;
import io.github.hectorvent.floci.services.autoscaling.model.AutoScalingGroup;
import io.github.hectorvent.floci.services.autoscaling.model.InstanceRefresh;
import io.github.hectorvent.floci.services.autoscaling.model.InstanceRefreshReplacement;
import io.github.hectorvent.floci.services.autoscaling.model.MixedInstancesPolicy;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.Ec2UserData;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.InstanceState;
import io.github.hectorvent.floci.services.ec2.model.LaunchTemplate;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import io.github.hectorvent.floci.services.ec2.model.Tag;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.elbv2.model.TargetDescription;
import io.github.hectorvent.floci.services.elbv2.model.TargetGroup;
import io.github.hectorvent.floci.services.elbv2.model.TargetHealth;
import io.github.hectorvent.floci.services.ssm.SsmCommandService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doThrow;

class AutoScalingReconcilerTest {

    @Test
    void pendingInstancesCountAsActiveCapacity() {
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.getInstances().add(instance("Pending"));
        asg.getInstances().add(instance("InService"));
        asg.getInstances().add(instance("Terminating"));
        asg.getInstances().add(instance("Terminated"));
        asg.getInstances().add(instance("Detached"));

        assertEquals(2, AutoScalingReconciler.activeCapacity(asg));
    }

    @Test
    void refreshOneHundredOneHundredLaunchesBeforeTerminatingOriginal() {
        RefreshFixture fixture = refreshFixture(1, 100, 100, 0);

        fixture.reconciler().reconcile(fixture.asg());

        assertEquals(List.of("i-original", "i-replacement"), fixture.asg().getInstances().stream()
                .map(AsgInstance::getInstanceId).toList());
        assertEquals("InService", fixture.asg().getInstances().getFirst().getLifecycleState());
        verify(fixture.ec2Service(), never()).terminateInstances("us-east-1", List.of("i-original"));
    }

    @Test
    void refreshNinetyOneHundredMarksAtMostOneOfTenUnavailableBeforeLaunch() {
        RefreshFixture fixture = refreshFixture(10, 90, 100, 0);

        fixture.reconciler().reconcile(fixture.asg());

        assertEquals(9, fixture.asg().getInstances().stream()
                .filter(instance -> "InService".equals(instance.getLifecycleState())).count());
        assertEquals(1, fixture.asg().getInstances().stream()
                .filter(instance -> "Standby".equals(instance.getLifecycleState())).count());
        assertEquals(1, fixture.asg().getInstances().stream()
                .filter(instance -> "Pending".equals(instance.getLifecycleState())).count());
        verify(fixture.ec2Service(), never()).terminateInstances(eq("us-east-1"), anyList());
    }

    @Test
    void refreshSurgeCeilingRoundsUpForSmallGroups() {
        RefreshFixture fixture = refreshFixture(3, 100, 120, 0);

        fixture.reconciler().reconcile(fixture.asg());

        assertEquals(4, fixture.asg().getInstances().size());
        assertEquals(3, fixture.asg().getInstances().stream()
                .filter(instance -> "InService".equals(instance.getLifecycleState())).count());
        assertEquals(1, fixture.asg().getInstances().stream()
                .filter(instance -> "Pending".equals(instance.getLifecycleState())).count());
        verify(fixture.ec2Service(), never()).terminateInstances(eq("us-east-1"), anyList());
    }

    @Test
    void refreshLaunchFailurePreservesOriginalAndFailsRefresh() {
        RefreshFixture fixture = refreshFixture(1, 100, 100, 0);
        when(fixture.ec2Service().runInstancesWithUserData(
                eq("us-east-1"), eq("ami-refresh"), eq("t3.small"), eq(1), eq(1),
                eq(null), eq(List.of()), eq(null), anyString(), eq(List.of()),
                isNull(Ec2UserData.class), eq(null)))
                .thenThrow(new IllegalStateException("capacity unavailable"));

        fixture.reconciler().reconcile(fixture.asg());

        assertEquals("InService", fixture.asg().getInstances().getFirst().getLifecycleState());
        verify(fixture.asgService()).failInstanceRefresh(
                eq(fixture.refresh()), org.mockito.ArgumentMatchers.contains("capacity unavailable"),
                eq(Instant.parse("2026-07-19T12:00:00Z")));
    }

    @Test
    void refreshWaitsForExactTargetHealthAndWarmupBeforeTermination() {
        RefreshFixture fixture = refreshFixture(1, 100, 100, 60);
        String targetGroupArn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/app/123";
        fixture.asg().setTargetGroupARNs(List.of(targetGroupArn));
        fixture.reconciler().reconcile(fixture.asg());
        AsgInstance replacement = fixture.asg().getInstances().get(1);
        replacement.setLifecycleState("InService");
        TargetHealth initial = targetHealth("i-replacement");
        initial.setState("initial");
        when(fixture.elbV2Service().describeTargetHealth("us-east-1", targetGroupArn, List.of()))
                .thenReturn(List.of(initial));

        fixture.reconciler().reconcile(fixture.asg());
        verify(fixture.ec2Service(), never()).terminateInstances("us-east-1", List.of("i-original"));

        initial.setState("healthy");
        fixture.reconciler().reconcile(fixture.asg());
        assertEquals("Warming", fixture.refresh().getReplacements().getFirst().getPhase());
        verify(fixture.ec2Service(), never()).terminateInstances("us-east-1", List.of("i-original"));
    }

    @Test
    void refreshUnhealthyTargetFailsAndPreservesOriginal() {
        RefreshFixture fixture = refreshFixture(1, 100, 100, 0);
        String targetGroupArn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/app/123";
        fixture.asg().setTargetGroupARNs(List.of(targetGroupArn));
        fixture.reconciler().reconcile(fixture.asg());
        fixture.asg().getInstances().get(1).setLifecycleState("InService");
        TargetHealth unhealthy = targetHealth("i-replacement");
        unhealthy.setState("unhealthy");
        when(fixture.elbV2Service().describeTargetHealth("us-east-1", targetGroupArn, List.of()))
                .thenReturn(List.of(unhealthy));

        fixture.reconciler().reconcile(fixture.asg());

        assertEquals("InService", fixture.asg().getInstances().getFirst().getLifecycleState());
        verify(fixture.asgService()).failInstanceRefresh(
                eq(fixture.refresh()), org.mockito.ArgumentMatchers.contains("is unhealthy"),
                eq(Instant.parse("2026-07-19T12:00:00Z")));
        verify(fixture.ec2Service(), never()).terminateInstances("us-east-1", List.of("i-original"));
    }

    @Test
    void refreshRecoversPersistedLaunchWithoutLaunchingDuplicate() {
        RefreshFixture fixture = refreshFixture(1, 100, 100, 0);
        InstanceRefreshReplacement pair = fixture.refresh().getReplacements().getFirst();
        pair.setPhase("Launching");
        pair.setLaunchClientToken("refresh-1:i-original");
        Instance launched = new Instance();
        launched.setInstanceId("i-recovered");
        launched.setClientToken(pair.getLaunchClientToken());
        Reservation recovered = new Reservation();
        recovered.setInstances(List.of(launched));
        when(fixture.ec2Service().describeInstances("us-east-1", List.of(), Map.of()))
                .thenReturn(List.of(recovered));

        fixture.reconciler().reconcile(fixture.asg());

        assertEquals("i-recovered", pair.getReplacementInstanceId());
        assertEquals(List.of("i-original", "i-recovered"), fixture.asg().getInstances().stream()
                .map(AsgInstance::getInstanceId).toList());
        verify(fixture.ec2Service(), never()).runInstancesWithUserData(
                eq("us-east-1"), eq("ami-refresh"), eq("t3.small"), eq(1), eq(1),
                eq(null), eq(List.of()), eq(null), anyString(), eq(List.of()),
                isNull(Ec2UserData.class), eq(null));
    }

    @Test
    void refreshTerminationFailureKeepsOriginalMembershipAndFailsRefresh() {
        RefreshFixture fixture = refreshFixture(1, 100, 100, 0);
        fixture.reconciler().reconcile(fixture.asg());
        AsgInstance replacement = fixture.asg().getInstances().get(1);
        replacement.setLifecycleState("InService");
        fixture.refresh().getReplacements().getFirst().setReadyTime(Instant.parse("2026-07-19T11:59:00Z"));
        doThrow(new IllegalStateException("termination denied"))
                .when(fixture.ec2Service()).terminateInstances("us-east-1", List.of("i-original"));

        fixture.reconciler().reconcile(fixture.asg());

        assertEquals(List.of("i-original", "i-replacement"), fixture.asg().getInstances().stream()
                .map(AsgInstance::getInstanceId).toList());
        verify(fixture.asgService()).failInstanceRefresh(
                eq(fixture.refresh()), org.mockito.ArgumentMatchers.contains("termination denied"),
                eq(Instant.parse("2026-07-19T12:00:00Z")));
    }

    @Test
    void refreshTargetDeregistrationFailurePreservesOriginalAndStopsBatch() {
        RefreshFixture fixture = refreshFixture(1, 100, 100, 0);
        String targetGroupArn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/app/123";
        fixture.asg().setTargetGroupARNs(List.of(targetGroupArn));
        fixture.reconciler().reconcile(fixture.asg());
        AsgInstance replacement = fixture.asg().getInstances().get(1);
        replacement.setLifecycleState("InService");
        fixture.refresh().getReplacements().getFirst().setReadyTime(Instant.parse("2026-07-19T11:59:00Z"));
        TargetHealth healthy = targetHealth("i-replacement");
        healthy.setState("healthy");
        when(fixture.elbV2Service().describeTargetHealth("us-east-1", targetGroupArn, List.of()))
                .thenReturn(List.of(healthy));
        doThrow(new IllegalStateException("deregistration denied"))
                .when(fixture.elbV2Service()).deregisterTargets(
                        eq("us-east-1"), eq(targetGroupArn), anyList());

        fixture.reconciler().reconcile(fixture.asg());

        assertEquals("InService", fixture.asg().getInstances().getFirst().getLifecycleState());
        verify(fixture.ec2Service(), never()).terminateInstances("us-east-1", List.of("i-original"));
        verify(fixture.asgService()).failInstanceRefresh(
                eq(fixture.refresh()), org.mockito.ArgumentMatchers.contains("deregistration denied"),
                eq(Instant.parse("2026-07-19T12:00:00Z")));
    }

    @Test
    void reconcileWithoutRefreshUsesNormalCapacityPath() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(0);

        reconciler.reconcile(asg);

        verify(asgService).saveAutoScalingGroup(asg);
    }

    @Test
    void scaleOutUsesRequestedLaunchTemplateVersionData() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(1);
        asg.setLaunchTemplateId("lt-123");
        asg.setLaunchTemplateVersion("1");
        asg.getTags().put("job-id", "2001");
        asg.getTags().put("control-plane-only", "true");
        asg.getTagPropagateAtLaunch().put("job-id", true);
        asg.getTagPropagateAtLaunch().put("control-plane-only", false);

        LaunchTemplate launchTemplate = new LaunchTemplate();
        launchTemplate.setLaunchTemplateId("lt-123");
        LaunchTemplate version = new LaunchTemplate();
        version.setLatestVersionNumber("1");
        version.setImageId("ami-version-1");
        version.setInstanceType("t3.micro");
        version.setEncodedUserData("/wAJ");
        version.setIamInstanceProfileArn("arn:aws:iam::000000000000:instance-profile/app-profile");
        List<Tag> instanceTags = List.of(new Tag("app.ClusterId", "development"));
        List<Tag> propagatedTags = List.of(new Tag("app.ClusterId", "development"), new Tag("job-id", "2001"));
        version.setInstanceTags(instanceTags);
        when(ec2Service.describeLaunchTemplates("us-east-1", List.of("lt-123"), List.of(), Map.of()))
                .thenReturn(List.of(launchTemplate));
        when(ec2Service.describeLaunchTemplateVersions("us-east-1", "lt-123", null, List.of("1")))
                .thenReturn(List.of(version));
        Instance ec2Instance = new Instance();
        ec2Instance.setInstanceId("i-launched");
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(ec2Instance));
        when(ec2Service.runInstancesWithUserData(eq("us-east-1"), eq("ami-version-1"), eq("t3.micro"),
                eq(1), eq(1), eq(null), eq(List.of()), eq(null), eq(null),
                anyList(), org.mockito.ArgumentMatchers.any(Ec2UserData.class),
                eq("arn:aws:iam::000000000000:instance-profile/app-profile"))).thenReturn(reservation);

        reconciler.reconcile(asg);

        assertEquals(1, asg.getInstances().size());
        assertEquals("i-launched", asg.getInstances().getFirst().getInstanceId());
        assertEquals("lt-123", asg.getInstances().getFirst().getLaunchTemplateId());
        assertEquals("1", asg.getInstances().getFirst().getLaunchTemplateVersion());
        ArgumentCaptor<List<Tag>> tags = ArgumentCaptor.captor();
        ArgumentCaptor<Ec2UserData> userData = ArgumentCaptor.forClass(Ec2UserData.class);
        verify(ec2Service).runInstancesWithUserData(eq("us-east-1"), eq("ami-version-1"), eq("t3.micro"),
                eq(1), eq(1), eq(null), eq(List.of()), eq(null), eq(null),
                tags.capture(), userData.capture(),
                eq("arn:aws:iam::000000000000:instance-profile/app-profile"));
        assertEquals("/wAJ", userData.getValue().encoded());
        assertEquals(propagatedTags.size(), tags.getValue().size());
        assertEquals("app.ClusterId", tags.getValue().get(0).getKey());
        assertEquals("development", tags.getValue().get(0).getValue());
        assertEquals("job-id", tags.getValue().get(1).getKey());
        assertEquals("2001", tags.getValue().get(1).getValue());
    }

    @Test
    void scaleOutStoresResolvedLaunchTemplateVersionForAliases() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(1);
        asg.setLaunchTemplateId("lt-123");
        asg.setLaunchTemplateVersion("$Latest");

        LaunchTemplate launchTemplate = new LaunchTemplate();
        launchTemplate.setLaunchTemplateId("lt-123");
        LaunchTemplate version = new LaunchTemplate();
        version.setLatestVersionNumber("7");
        version.setImageId("ami-version-7");
        version.setInstanceType("t3.micro");
        when(ec2Service.describeLaunchTemplates("us-east-1", List.of("lt-123"), List.of(), Map.of()))
                .thenReturn(List.of(launchTemplate));
        when(ec2Service.describeLaunchTemplateVersions("us-east-1", "lt-123", null, List.of("$Latest")))
                .thenReturn(List.of(version));
        Instance ec2Instance = new Instance();
        ec2Instance.setInstanceId("i-launched");
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(ec2Instance));
        when(ec2Service.runInstancesWithUserData(eq("us-east-1"), eq("ami-version-7"), eq("t3.micro"),
                eq(1), eq(1), eq(null), eq(List.of()), eq(null), eq(null),
                eq(List.of()), eq(null), eq(null))).thenReturn(reservation);

        reconciler.reconcile(asg);

        assertEquals("$Latest", asg.getLaunchTemplateVersion());
        assertEquals("7", asg.getInstances().getFirst().getLaunchTemplateVersion());
    }

    @Test
    void scaleOutUsesMixedInstancesLaunchTemplateSpecification() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(1);
        MixedInstancesPolicy policy = new MixedInstancesPolicy();
        MixedInstancesPolicy.LaunchTemplate launchTemplatePolicy =
                new MixedInstancesPolicy.LaunchTemplate();
        MixedInstancesPolicy.LaunchTemplateSpecification specification =
                new MixedInstancesPolicy.LaunchTemplateSpecification();
        specification.setLaunchTemplateId("lt-123");
        specification.setVersion("3");
        launchTemplatePolicy.setLaunchTemplateSpecification(specification);
        MixedInstancesPolicy.LaunchTemplateOverride override =
                new MixedInstancesPolicy.LaunchTemplateOverride();
        override.setInstanceType("t3.small");
        launchTemplatePolicy.setOverrides(List.of(override));
        policy.setLaunchTemplate(launchTemplatePolicy);
        asg.setMixedInstancesPolicy(policy);

        LaunchTemplate launchTemplate = new LaunchTemplate();
        launchTemplate.setLaunchTemplateId("lt-123");
        LaunchTemplate version = new LaunchTemplate();
        version.setLatestVersionNumber("3");
        version.setImageId("ami-version-3");
        version.setInstanceType("t3.micro");
        when(ec2Service.describeLaunchTemplates("us-east-1", List.of("lt-123"), List.of(), Map.of()))
                .thenReturn(List.of(launchTemplate));
        when(ec2Service.describeLaunchTemplateVersions("us-east-1", "lt-123", null, List.of("3")))
                .thenReturn(List.of(version));
        Instance ec2Instance = new Instance();
        ec2Instance.setInstanceId("i-launched");
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(ec2Instance));
        when(ec2Service.runInstancesWithUserData(eq("us-east-1"), eq("ami-version-3"), eq("t3.small"),
                eq(1), eq(1), eq(null), eq(List.of()), eq(null), eq(null),
                eq(List.of()), eq(null), eq(null))).thenReturn(reservation);

        reconciler.reconcile(asg);

        assertEquals(1, asg.getInstances().size());
        assertEquals("i-launched", asg.getInstances().getFirst().getInstanceId());
        assertEquals("lt-123", asg.getInstances().getFirst().getLaunchTemplateId());
        assertEquals("3", asg.getInstances().getFirst().getLaunchTemplateVersion());
        assertEquals("t3.small", asg.getInstances().getFirst().getInstanceType());
        verify(ec2Service).runInstancesWithUserData(eq("us-east-1"), eq("ami-version-3"), eq("t3.small"),
                eq(1), eq(1), eq(null), eq(List.of()), eq(null), eq(null),
                eq(List.of()), eq(null), eq(null));
    }

    @Test
    void reconcileDeregistersStaleAsgMemberAndPreservesExternalTarget() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        String targetGroupArn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/app/123";
        AutoScalingGroup asg = targetGroupAsg(targetGroupArn, "i-active", "i-stale");
        asg.setDesiredCapacity(1);
        when(ec2Service.isInstanceContainerRunning("i-active")).thenReturn(true);
        when(ec2Service.isInstanceContainerRunning("i-stale")).thenReturn(false);
        when(elbV2Service.describeTargetGroups("us-east-1", null, List.of(targetGroupArn), List.of()))
                .thenReturn(List.of(targetGroup(targetGroupArn, 8080)));
        when(elbV2Service.describeTargetHealth("us-east-1", targetGroupArn, List.of()))
                .thenReturn(List.of(
                        targetHealth("i-active", 8080),
                        targetHealth("i-stale", 8080),
                        targetHealth("i-external", 8080)));

        reconciler.reconcile(asg);

        ArgumentCaptor<List<TargetDescription>> targets = ArgumentCaptor.captor();
        verify(elbV2Service).deregisterTargets(
                eq("us-east-1"),
                eq(targetGroupArn),
                targets.capture());
        assertEquals(List.of("i-stale"), targets.getValue().stream().map(TargetDescription::getId).toList());
        assertEquals(List.of("i-active"), asg.getInstances().stream().map(AsgInstance::getInstanceId).toList());
        verify(elbV2Service, never()).registerTargets(eq("us-east-1"), eq(targetGroupArn), anyList());
        verify(asgService, times(2)).saveAutoScalingGroup(asg);
        verify(ec2Service, never()).terminateInstances(asg.getRegion(), List.of("i-active"));
    }

    @Test
    void reconcileRegistersOnlyMissingInServiceTargetsAtEffectiveTargetGroupPort() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        String targetGroupArn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/app/123";
        AutoScalingGroup asg = targetGroupAsg(targetGroupArn, "i-registered", "i-missing");
        when(ec2Service.isInstanceContainerRunning("i-registered")).thenReturn(true);
        when(ec2Service.isInstanceContainerRunning("i-missing")).thenReturn(true);
        when(elbV2Service.describeTargetGroups("us-east-1", null, List.of(targetGroupArn), List.of()))
                .thenReturn(List.of(targetGroup(targetGroupArn, 8080)));
        when(elbV2Service.describeTargetHealth("us-east-1", targetGroupArn, List.of()))
                .thenReturn(List.of(targetHealth("i-registered", 8080)));

        reconciler.reconcile(asg);

        ArgumentCaptor<List<TargetDescription>> targets = ArgumentCaptor.captor();
        verify(elbV2Service).registerTargets(eq("us-east-1"), eq(targetGroupArn), targets.capture());
        assertEquals(1, targets.getValue().size());
        assertEquals("i-missing", targets.getValue().getFirst().getId());
        assertEquals(8080, targets.getValue().getFirst().getPort());
    }

    @Test
    void reconcileDoesNotRegisterAnExistingEffectivePortTargetAgain() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        String targetGroupArn = "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/app/123";
        AutoScalingGroup asg = targetGroupAsg(targetGroupArn, "i-registered");
        when(ec2Service.isInstanceContainerRunning("i-registered")).thenReturn(true);
        when(elbV2Service.describeTargetGroups("us-east-1", null, List.of(targetGroupArn), List.of()))
                .thenReturn(List.of(targetGroup(targetGroupArn, 8080)));
        when(elbV2Service.describeTargetHealth("us-east-1", targetGroupArn, List.of()))
                .thenReturn(List.of(targetHealth("i-registered", 8080)));

        reconciler.reconcile(asg);
        reconciler.reconcile(asg);

        verify(elbV2Service, never()).registerTargets(eq("us-east-1"), eq(targetGroupArn), anyList());
    }

    @Test
    void reconcileIsolatesTargetHealthFailuresByTargetGroup() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        String failingTargetGroupArn =
                "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/failing/123";
        String healthyTargetGroupArn =
                "arn:aws:elasticloadbalancing:us-east-1:000000000000:targetgroup/healthy/456";
        AutoScalingGroup asg = targetGroupAsg(failingTargetGroupArn, "i-active");
        asg.setTargetGroupARNs(List.of(failingTargetGroupArn, healthyTargetGroupArn));
        when(ec2Service.isInstanceContainerRunning("i-active")).thenReturn(true);
        when(elbV2Service.describeTargetGroups("us-east-1", null, List.of(failingTargetGroupArn), List.of()))
                .thenReturn(List.of(targetGroup(failingTargetGroupArn, 8080)));
        when(elbV2Service.describeTargetGroups("us-east-1", null, List.of(healthyTargetGroupArn), List.of()))
                .thenReturn(List.of(targetGroup(healthyTargetGroupArn, 9090)));
        when(elbV2Service.describeTargetHealth("us-east-1", failingTargetGroupArn, List.of()))
                .thenThrow(new IllegalStateException("target health unavailable"));
        when(elbV2Service.describeTargetHealth("us-east-1", healthyTargetGroupArn, List.of()))
                .thenReturn(List.of());

        reconciler.reconcile(asg);

        ArgumentCaptor<List<TargetDescription>> targets = ArgumentCaptor.captor();
        verify(elbV2Service).registerTargets(eq("us-east-1"), eq(healthyTargetGroupArn), targets.capture());
        assertEquals("i-active", targets.getValue().getFirst().getId());
        assertEquals(9090, targets.getValue().getFirst().getPort());
        verify(elbV2Service, never()).registerTargets(eq("us-east-1"), eq(failingTargetGroupArn), anyList());
    }

    @Test
    void reconcileKeepsPendingInstancesWhileContainerLaunchIsStillInFlight() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(1);
        asg.getInstances().add(instance("i-pending", "Pending"));

        Instance ec2Instance = new Instance();
        ec2Instance.setInstanceId("i-pending");
        ec2Instance.setState(InstanceState.pending());
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(ec2Instance));
        when(ec2Service.describeInstances("us-east-1", List.of("i-pending"), null))
                .thenReturn(List.of(reservation));
        when(ec2Service.isInstanceContainerRunning("i-pending")).thenReturn(false);

        reconciler.reconcile(asg);

        assertEquals(1, asg.getInstances().size());
        assertEquals("i-pending", asg.getInstances().getFirst().getInstanceId());
        verify(ec2Service, never()).runInstancesWithUserData(
                eq("us-east-1"),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyInt(),
                org.mockito.ArgumentMatchers.anyInt(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void reconcilePrunesPendingInstancesWhenEc2InstanceIsTerminal() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(0);
        asg.getInstances().add(instance("i-dead", "Pending"));

        Instance ec2Instance = new Instance();
        ec2Instance.setInstanceId("i-dead");
        ec2Instance.setState(InstanceState.terminated());
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(ec2Instance));
        when(ec2Service.describeInstances("us-east-1", List.of("i-dead"), null))
                .thenReturn(List.of(reservation));

        reconciler.reconcile(asg);

        assertEquals(0, asg.getInstances().size());
        verify(asgService).recordActivity(
                eq("us-east-1"),
                eq("app-asg"),
                eq("Removing stale EC2 instance reference(s): [i-dead]"),
                eq("Persisted Auto Scaling state referenced instance containers that are no longer running."),
                eq("Successful"));
    }

    @Test
    void reconcileFailsActiveSsmInvocationsBeforePruningStaleInstance() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        SsmCommandService ssmCommandService = mock(SsmCommandService.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(
                asgService, ec2Service, elbV2Service, ssmCommandService);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(0);
        asg.getInstances().add(instance("i-dead", "Pending"));

        Instance ec2Instance = new Instance();
        ec2Instance.setInstanceId("i-dead");
        ec2Instance.setState(InstanceState.terminated());
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(ec2Instance));
        when(ec2Service.describeInstances("us-east-1", List.of("i-dead"), null))
                .thenReturn(List.of(reservation));
        when(ssmCommandService.failActiveInvocationsForInstances("us-east-1", Set.of("i-dead"), "Undeliverable"))
                .thenReturn(1);

        reconciler.reconcile(asg);

        assertEquals(0, asg.getInstances().size());
        verify(ssmCommandService).failActiveInvocationsForInstances("us-east-1", Set.of("i-dead"), "Undeliverable");
    }

    @Test
    void reconcilePromotesPendingAsgInstanceWhenEc2InstanceIsRunning() {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(asgService, ec2Service, elbV2Service);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(1);
        asg.getInstances().add(instance("i-pending", "Pending"));

        Instance ec2Instance = new Instance();
        ec2Instance.setInstanceId("i-pending");
        ec2Instance.setState(InstanceState.running());
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(ec2Instance));
        when(ec2Service.describeInstances(asg.getRegion(), List.of("i-pending"), null))
                .thenReturn(List.of(reservation));
        when(ec2Service.isInstanceContainerRunning("i-pending")).thenReturn(true);

        reconciler.reconcile(asg);

        assertEquals("InService", asg.getInstances().getFirst().getLifecycleState());
        assertEquals("Healthy", asg.getInstances().getFirst().getHealthStatus());
        verify(asgService).recordActivity(
                eq(asg.getRegion()),
                eq(asg.getAutoScalingGroupName()),
                eq("Launching a new EC2 instance: i-pending"),
                eq("An instance was started in response to a desired capacity change."),
                eq("Successful"));
        verify(asgService, times(2)).saveAutoScalingGroup(asg);
    }

    private static RefreshFixture refreshFixture(int desired, int minHealthy, int maxHealthy, int warmup) {
        AutoScalingService asgService = mock(AutoScalingService.class);
        Ec2Service ec2Service = mock(Ec2Service.class);
        ElbV2Service elbV2Service = mock(ElbV2Service.class);
        Clock clock = Clock.fixed(Instant.parse("2026-07-19T12:00:00Z"), ZoneOffset.UTC);
        AutoScalingReconciler reconciler = new AutoScalingReconciler(
                asgService, ec2Service, elbV2Service, null, clock);
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(desired);
        asg.setMaxSize(Math.max(desired + 1, 2));
        asg.setLaunchTemplateId("lt-source");
        asg.setLaunchTemplateVersion("1");
        for (int i = 0; i < desired; i++) {
            String id = i == 0 ? "i-original" : "i-original-" + i;
            AsgInstance instance = instance(id, "InService");
            instance.setLaunchTemplateId("lt-source");
            instance.setLaunchTemplateVersion("1");
            instance.setInstanceType("t3.micro");
            asg.getInstances().add(instance);
            when(ec2Service.isInstanceContainerRunning(id)).thenReturn(true);
        }

        InstanceRefresh refresh = new InstanceRefresh();
        refresh.setInstanceRefreshId("refresh-1");
        refresh.setRegion("us-east-1");
        refresh.setAutoScalingGroupName("app-asg");
        refresh.setStatus("InProgress");
        refresh.setPhase("Pending");
        refresh.setStartTime(Instant.parse("2026-07-19T11:00:00Z"));
        refresh.setMinHealthyPercentage(minHealthy);
        refresh.setMaxHealthyPercentage(maxHealthy);
        refresh.setInstanceWarmup(warmup);
        refresh.setDesiredLaunchTemplateId("lt-refresh");
        refresh.setDesiredLaunchTemplateVersion("2");
        refresh.setCandidateInstanceIds(asg.getInstances().stream().map(AsgInstance::getInstanceId).toList());
        refresh.setReplacements(refresh.getCandidateInstanceIds().stream().map(id -> {
            InstanceRefreshReplacement replacement = new InstanceRefreshReplacement();
            replacement.setOriginalInstanceId(id);
            replacement.setPhase("Pending");
            return replacement;
        }).toList());
        refresh.setInstancesToUpdate(desired);
        when(asgService.activeInstanceRefresh("us-east-1", "app-asg"))
                .thenReturn(java.util.Optional.of(refresh));
        when(ec2Service.isInstanceContainerRunning("i-replacement")).thenReturn(true);

        LaunchTemplate template = new LaunchTemplate();
        template.setLaunchTemplateId("lt-refresh");
        LaunchTemplate version = new LaunchTemplate();
        version.setLatestVersionNumber("2");
        version.setImageId("ami-refresh");
        version.setInstanceType("t3.small");
        when(ec2Service.describeLaunchTemplates("us-east-1", List.of("lt-refresh"), List.of(), Map.of()))
                .thenReturn(List.of(template));
        when(ec2Service.describeLaunchTemplateVersions("us-east-1", "lt-refresh", null, List.of("2")))
                .thenReturn(List.of(version));
        Instance launched = new Instance();
        launched.setInstanceId("i-replacement");
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(launched));
        when(ec2Service.runInstancesWithUserData(
                eq("us-east-1"), eq("ami-refresh"), eq("t3.small"), eq(1), eq(1),
                eq(null), eq(List.of()), eq(null), anyString(), eq(List.of()),
                isNull(Ec2UserData.class), eq(null)))
                .thenReturn(reservation);
        return new RefreshFixture(asgService, ec2Service, elbV2Service, reconciler, asg, refresh);
    }

    private record RefreshFixture(AutoScalingService asgService, Ec2Service ec2Service,
                                  ElbV2Service elbV2Service, AutoScalingReconciler reconciler,
                                  AutoScalingGroup asg, InstanceRefresh refresh) {}

    private static AsgInstance instance(String lifecycleState) {
        AsgInstance instance = new AsgInstance();
        instance.setLifecycleState(lifecycleState);
        return instance;
    }

    private static AsgInstance instance(String instanceId, String lifecycleState) {
        AsgInstance instance = instance(lifecycleState);
        instance.setInstanceId(instanceId);
        instance.setHealthStatus("Healthy");
        return instance;
    }

    private static AutoScalingGroup targetGroupAsg(String targetGroupArn, String... instanceIds) {
        AutoScalingGroup asg = new AutoScalingGroup();
        asg.setRegion("us-east-1");
        asg.setAutoScalingGroupName("app-asg");
        asg.setDesiredCapacity(instanceIds.length);
        asg.setTargetGroupARNs(List.of(targetGroupArn));
        for (String instanceId : instanceIds) {
            asg.getInstances().add(instance(instanceId, "InService"));
        }
        return asg;
    }

    private static TargetGroup targetGroup(String targetGroupArn, int port) {
        TargetGroup targetGroup = new TargetGroup();
        targetGroup.setTargetGroupArn(targetGroupArn);
        targetGroup.setPort(port);
        return targetGroup;
    }

    private static TargetHealth targetHealth(String instanceId) {
        return targetHealth(instanceId, null);
    }

    private static TargetHealth targetHealth(String instanceId, Integer port) {
        TargetDescription target = new TargetDescription();
        target.setId(instanceId);
        target.setPort(port);
        TargetHealth health = new TargetHealth();
        health.setTarget(target);
        return health;
    }
}
