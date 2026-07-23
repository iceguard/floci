package io.github.hectorvent.floci.services.autoscaling;

import io.github.hectorvent.floci.services.autoscaling.model.AsgInstance;
import io.github.hectorvent.floci.services.autoscaling.model.AutoScalingGroup;
import io.github.hectorvent.floci.services.autoscaling.model.InstanceRefresh;
import io.github.hectorvent.floci.services.autoscaling.model.InstanceRefreshReplacement;
import io.github.hectorvent.floci.services.autoscaling.model.LaunchConfiguration;
import io.github.hectorvent.floci.services.autoscaling.model.MixedInstancesPolicy;
import io.github.hectorvent.floci.services.autoscaling.model.SuspendedProcess;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.Ec2UserData;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.LaunchTemplate;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import io.github.hectorvent.floci.services.elbv2.ElbV2HealthChecker;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.elbv2.model.TargetDescription;
import io.github.hectorvent.floci.services.elbv2.model.TargetGroup;
import io.github.hectorvent.floci.services.elbv2.model.TargetHealth;
import io.github.hectorvent.floci.services.ssm.SsmCommandService;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import io.quarkus.runtime.StartupEvent;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@ApplicationScoped
public class AutoScalingReconciler {

    private static final Logger LOG = Logger.getLogger(AutoScalingReconciler.class);

    private final AutoScalingService asgService;
    private final Ec2Service ec2Service;
    private final ElbV2Service elbV2Service;
    private final SsmCommandService ssmCommandService;
    private final Clock clock;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(
            r -> new Thread(r, "asg-reconciler"));

    @Inject
    AutoScalingReconciler(AutoScalingService asgService, Ec2Service ec2Service,
                          ElbV2Service elbV2Service, SsmCommandService ssmCommandService) {
        this(asgService, ec2Service, elbV2Service, ssmCommandService, Clock.systemUTC());
    }

    AutoScalingReconciler(AutoScalingService asgService, Ec2Service ec2Service,
                          ElbV2Service elbV2Service, SsmCommandService ssmCommandService,
                          Clock clock) {
        this.asgService = asgService;
        this.ec2Service = ec2Service;
        this.elbV2Service = elbV2Service;
        this.ssmCommandService = ssmCommandService;
        this.clock = clock;
    }

    AutoScalingReconciler(AutoScalingService asgService, Ec2Service ec2Service,
                          ElbV2Service elbV2Service) {
        this(asgService, ec2Service, elbV2Service, null);
    }

    @PostConstruct
    void start() {
        scheduler.scheduleAtFixedRate(this::reconcileAll, 5, 10, TimeUnit.SECONDS);
    }

    void onStart(@Observes StartupEvent event) {
        LOG.debug("Auto Scaling reconciler initialized");
    }

    void reconcileAll() {
        for (AutoScalingGroup asg : asgService.describeAutoScalingGroups(null, null)) {
            try {
                reconcile(asg);
            } catch (Exception e) {
                LOG.warnv("Reconcile failed for ASG {0}: {1}", asg.getAutoScalingGroupName(), e.getMessage());
            }
        }
    }

    public void reconcile(AutoScalingGroup asg) {
        removeTerminatingInstances(asg);
        List<String> staleInstanceIds = removeStaleInstances(asg);
        if (!staleInstanceIds.isEmpty()) {
            deregisterFromTargetGroups(asg, staleInstanceIds);
        }
        promoteReadyInstances(asg);
        reconcileActiveTargetRegistrations(asg);

        Optional<InstanceRefresh> activeRefresh = asgService.activeInstanceRefresh(
                asg.getRegion(), asg.getAutoScalingGroupName());
        if (activeRefresh.isPresent()) {
            reconcileInstanceRefresh(asg, activeRefresh.get());
            asgService.saveAutoScalingGroup(asg);
            return;
        }

        long activeCapacity = activeCapacity(asg);
        int desired = asg.getDesiredCapacity();

        if (activeCapacity < desired) {
            if (isProcessSuspended(asg, "Launch")) {
                LOG.debugv("ASG {0}: Launch process is suspended, skipping scale out",
                        asg.getAutoScalingGroupName());
            } else {
                scaleOut(asg, (int) (desired - activeCapacity));
            }
        } else if (activeCapacity > desired) {
            if (isProcessSuspended(asg, "Terminate")) {
                LOG.debugv("ASG {0}: Terminate process is suspended, skipping scale in",
                        asg.getAutoScalingGroupName());
            } else {
                scaleIn(asg, (int) (activeCapacity - desired));
            }
        }
        asgService.saveAutoScalingGroup(asg);
    }

    private static boolean isProcessSuspended(AutoScalingGroup asg, String processName) {
        return asg.getSuspendedProcesses().stream()
                .map(SuspendedProcess::getProcessName)
                .anyMatch(processName::equals);
    }

    private void reconcileInstanceRefresh(AutoScalingGroup asg, InstanceRefresh refresh) {
        Instant now = clock.instant();
        if ("RollbackInProgress".equals(refresh.getStatus())) {
            reconcileInstanceRefreshRollback(asg, refresh, now);
            return;
        }
        InstanceRefreshReplacement pair = refresh.getReplacements().stream()
                .filter(replacement -> !"Completed".equals(replacement.getPhase()))
                .filter(replacement -> !"Failed".equals(replacement.getPhase()))
                .findFirst()
                .orElse(null);
        if (pair == null) {
            asgService.completeInstanceRefresh(asg, refresh, now);
            return;
        }

        AsgInstance original = findAsgInstance(asg, pair.getOriginalInstanceId()).orElse(null);
        if (pair.getReplacementInstanceId() == null) {
            if (original == null) {
                failRefresh(asg, refresh, pair,
                        "Original instance " + pair.getOriginalInstanceId() + " is no longer available.", now);
                return;
            }
            if (!prepareCapacityForReplacement(asg, refresh, original)) {
                return;
            }
            try {
                AsgInstance replacement = recoverRefreshReplacement(asg, refresh, pair).orElse(null);
                if (replacement == null) {
                    pair.setLaunchClientToken(refresh.getInstanceRefreshId() + ":" + pair.getOriginalInstanceId());
                    pair.setPhase("Launching");
                    asgService.saveInstanceRefresh(refresh);
                    replacement = launchRefreshReplacement(asg, refresh, pair.getLaunchClientToken());
                }
                pair.setReplacementInstanceId(replacement.getInstanceId());
                pair.setPhase("Pending");
                refresh.setPhase("Replacing");
                updateRefreshProgress(refresh);
                asgService.saveInstanceRefresh(refresh);
            } catch (Exception e) {
                restoreOriginal(original);
                failRefresh(asg, refresh, pair, "Replacement launch failed: " + message(e), now);
            }
            return;
        }

        AsgInstance replacement = findAsgInstance(asg, pair.getReplacementInstanceId()).orElse(null);
        if (replacement == null) {
            restoreOriginal(original);
            failRefresh(asg, refresh, pair,
                    "Replacement instance " + pair.getReplacementInstanceId() + " failed before becoming ready.", now);
            return;
        }
        if (!"InService".equals(replacement.getLifecycleState())
                || !"Healthy".equals(replacement.getHealthStatus())) {
            pair.setReadyTime(null);
            pair.setPhase("Pending");
            asgService.saveInstanceRefresh(refresh);
            return;
        }
        TargetReadiness targetReadiness = targetReadiness(asg, replacement.getInstanceId());
        if (targetReadiness.failureReason() != null) {
            restoreOriginal(original);
            failRefresh(asg, refresh, pair, targetReadiness.failureReason(), now);
            return;
        }
        if (!targetReadiness.ready()) {
            pair.setReadyTime(null);
            pair.setPhase("Pending");
            asgService.saveInstanceRefresh(refresh);
            return;
        }
        if (pair.getReadyTime() == null) {
            pair.setReadyTime(now);
            pair.setPhase("Warming");
            asgService.saveInstanceRefresh(refresh);
            return;
        }
        int warmupSeconds = refresh.getInstanceWarmup() != null ? refresh.getInstanceWarmup() : 0;
        if (Duration.between(pair.getReadyTime(), now).getSeconds() < warmupSeconds) {
            return;
        }

        if (original != null) {
            try {
                deregisterRefreshOriginal(asg, original.getInstanceId());
                ec2Service.terminateInstances(asg.getRegion(), List.of(original.getInstanceId()));
                asg.getInstances().remove(original);
            } catch (Exception e) {
                restoreOriginal(original);
                if (original != null) {
                    registerWithTargetGroups(asg, original);
                }
                failRefresh(asg, refresh, pair, "Original termination failed: " + message(e), now);
                return;
            }
        }
        pair.setPhase("Completed");
        updateRefreshProgress(refresh);
        asgService.saveAutoScalingGroup(asg);
        asgService.saveInstanceRefresh(refresh);
        if (refresh.getInstancesToUpdate() == 0) {
            asgService.completeInstanceRefresh(asg, refresh, now);
        }
    }

    private boolean prepareCapacityForReplacement(AutoScalingGroup asg, InstanceRefresh refresh,
                                                  AsgInstance original) {
        int desired = asg.getDesiredCapacity();
        int active = (int) activeCapacity(asg);
        int healthy = (int) asg.getInstances().stream()
                .filter(instance -> "InService".equals(instance.getLifecycleState()))
                .filter(instance -> "Healthy".equals(instance.getHealthStatus()))
                .count();
        int minimumHealthy = (int) Math.ceil(desired * refresh.getMinHealthyPercentage() / 100.0);
        int maximumHealthy = (int) Math.ceil(desired * refresh.getMaxHealthyPercentage() / 100.0);
        boolean launchBeforeTerminate = minimumHealthy >= desired && maximumHealthy <= desired;
        int effectiveCeiling = launchBeforeTerminate ? Math.max(maximumHealthy, desired + 1) : maximumHealthy;
        if (active < effectiveCeiling) {
            return true;
        }
        if (healthy - 1 < minimumHealthy) {
            return false;
        }
        original.setLifecycleState("Standby");
        asgService.saveAutoScalingGroup(asg);
        return true;
    }

    private AsgInstance launchRefreshReplacement(AutoScalingGroup asg, InstanceRefresh refresh,
                                                 String clientToken) {
        AutoScalingGroup desiredSource = AutoScalingService.desiredLaunchSource(asg, refresh);
        LaunchSource launchSource = resolveLaunchSource(desiredSource);
        if (launchSource == null) {
            throw new IllegalStateException("No valid launch source is available");
        }
        String az = asg.getAvailabilityZones().isEmpty()
                ? asg.getRegion() + "a" : asg.getAvailabilityZones().getFirst();
        String subnetId = asg.getSubnetIds().isEmpty() ? null : asg.getSubnetIds().getFirst();
        Reservation reservation = ec2Service.runInstancesWithUserData(
                asg.getRegion(), launchSource.imageId(), launchSource.instanceType(), 1, 1,
                launchSource.keyName(), launchSource.securityGroupIds(), subnetId, clientToken,
                propagatedInstanceTags(asg, launchSource), launchSource.userData(),
                launchSource.iamInstanceProfile());
        if (reservation.getInstances() == null || reservation.getInstances().size() != 1) {
            throw new IllegalStateException("Replacement launch did not return exactly one instance");
        }
        return attachRefreshReplacement(
                asg, launchSource, reservation.getInstances().getFirst(), az, clientToken);
    }

    private Optional<AsgInstance> recoverRefreshReplacement(AutoScalingGroup asg, InstanceRefresh refresh,
                                                            InstanceRefreshReplacement pair) {
        if (!"Launching".equals(pair.getPhase()) || pair.getLaunchClientToken() == null) {
            return Optional.empty();
        }
        Optional<AsgInstance> existingMember = asg.getInstances().stream()
                .filter(instance -> pair.getLaunchClientToken().equals(instance.getLaunchClientToken()))
                .findFirst();
        if (existingMember.isPresent()) {
            return existingMember;
        }
        AutoScalingGroup desiredSource = AutoScalingService.desiredLaunchSource(asg, refresh);
        LaunchSource launchSource = resolveLaunchSource(desiredSource);
        if (launchSource == null) {
            throw new IllegalStateException("No valid launch source is available");
        }
        return ec2Service.describeInstances(asg.getRegion(), List.of(), Map.of()).stream()
                .flatMap(reservation -> reservation.getInstances().stream())
                .filter(instance -> pair.getLaunchClientToken().equals(instance.getClientToken()))
                .findFirst()
                .map(instance -> attachRefreshReplacement(asg, launchSource, instance,
                        instance.getPlacement() != null ? instance.getPlacement().getAvailabilityZone() : null,
                        pair.getLaunchClientToken()));
    }

    private AsgInstance attachRefreshReplacement(AutoScalingGroup asg, LaunchSource launchSource,
                                                 Instance ec2Instance, String availabilityZone,
                                                 String clientToken) {
        AsgInstance replacement = new AsgInstance();
        replacement.setInstanceId(ec2Instance.getInstanceId());
        replacement.setAvailabilityZone(availabilityZone != null ? availabilityZone
                : asg.getAvailabilityZones().isEmpty() ? asg.getRegion() + "a" : asg.getAvailabilityZones().getFirst());
        replacement.setLifecycleState("Pending");
        replacement.setHealthStatus("Healthy");
        replacement.setLaunchClientToken(clientToken);
        replacement.setLaunchConfigurationName(launchSource.launchConfigurationName());
        replacement.setLaunchTemplateId(launchSource.launchTemplateId());
        replacement.setLaunchTemplateName(launchSource.launchTemplateName());
        replacement.setLaunchTemplateVersion(launchSource.launchTemplateVersion());
        replacement.setInstanceType(launchSource.instanceType());
        asg.getInstances().add(replacement);
        asgService.saveAutoScalingGroup(asg);
        return replacement;
    }

    private TargetReadiness targetReadiness(AutoScalingGroup asg, String instanceId) {
        for (String targetGroupArn : asg.getTargetGroupARNs()) {
            List<TargetHealth> states;
            try {
                states = elbV2Service.describeTargetHealth(asg.getRegion(), targetGroupArn, List.of());
            } catch (Exception e) {
                return TargetReadiness.failure(
                        "Target health lookup failed for " + targetGroupArn + ": " + message(e));
            }
            TargetHealth targetHealth = states.stream()
                    .filter(state -> state.getTarget() != null)
                    .filter(state -> instanceId.equals(state.getTarget().getId()))
                    .findFirst()
                    .orElse(null);
            if (targetHealth == null || "unused".equals(targetHealth.getState())) {
                return TargetReadiness.failure("Replacement instance " + instanceId
                        + " is not registered with target group " + targetGroupArn + ".");
            }
            if ("initial".equals(targetHealth.getState())) {
                return TargetReadiness.pending();
            }
            if (!"healthy".equals(targetHealth.getState())) {
                return TargetReadiness.failure("Replacement instance " + instanceId + " is "
                        + targetHealth.getState() + " in target group " + targetGroupArn + ".");
            }
        }
        return TargetReadiness.satisfied();
    }

    private void failRefresh(AutoScalingGroup asg, InstanceRefresh refresh,
                             InstanceRefreshReplacement pair, String reason, Instant now) {
        pair.setPhase("Failed");
        pair.setFailureReason(reason);
        updateRefreshProgress(refresh);
        asgService.saveAutoScalingGroup(asg);
        if (Boolean.TRUE.equals(refresh.getAutoRollback())) {
            beginInstanceRefreshRollback(asg, refresh, reason, now);
        } else {
            asgService.failInstanceRefresh(refresh, reason, now);
        }
    }

    private void beginInstanceRefreshRollback(AutoScalingGroup asg, InstanceRefresh refresh,
                                              String reason, Instant now) {
        AutoScalingService.restoreSourceConfiguration(asg, refresh);
        refresh.setStatus("RollbackInProgress");
        refresh.setPhase("Rollback");
        refresh.setFailureReason(reason);
        refresh.setRollbackReason(reason);
        refresh.setRollbackStartTime(now);
        refresh.setRollbackFailureReason(null);
        for (InstanceRefreshReplacement replacement : refresh.getReplacements()) {
            if (replacement.getRollbackPhase() == null) {
                boolean originalStillPresent = findAsgInstance(asg, replacement.getOriginalInstanceId()).isPresent();
                Optional<AsgInstance> forward = findForwardReplacement(asg, replacement);
                if (replacement.getReplacementInstanceId() == null && forward.isPresent()) {
                    replacement.setReplacementInstanceId(forward.get().getInstanceId());
                }
                boolean forwardPresent = forward.isPresent();
                replacement.setRollbackPhase(originalStillPresent && !forwardPresent ? "Completed" : "Pending");
            }
        }
        updateRollbackProgress(refresh);
        refresh.setStatusReason("Instance refresh failed. Auto rollback in progress: " + reason);
        asgService.saveAutoScalingGroup(asg);
        asgService.saveInstanceRefresh(refresh);
    }

    private void reconcileInstanceRefreshRollback(AutoScalingGroup asg, InstanceRefresh refresh, Instant now) {
        InstanceRefreshReplacement pair = refresh.getReplacements().stream()
                .filter(replacement -> !"Completed".equals(replacement.getRollbackPhase()))
                .findFirst()
                .orElse(null);
        if (pair == null) {
            completeInstanceRefreshRollback(asg, refresh, now);
            return;
        }

        AsgInstance original = findAsgInstance(asg, pair.getOriginalInstanceId()).orElse(null);
        AsgInstance forward = findForwardReplacement(asg, pair).orElse(null);
        if (original != null) {
            restoreOriginal(original);
            try {
                if (forward != null) {
                    terminateRollbackMember(asg, forward);
                }
            } catch (Exception e) {
                failInstanceRefreshRollback(asg, refresh, pair,
                        "Failed to remove forward replacement " + forward.getInstanceId() + ": " + message(e), now);
                return;
            }
            pair.setRollbackPhase("Completed");
            pair.setRollbackFailureReason(null);
            updateRollbackProgress(refresh);
            asgService.saveAutoScalingGroup(asg);
            asgService.saveInstanceRefresh(refresh);
            return;
        }
        if (forward == null) {
            failInstanceRefreshRollback(asg, refresh, pair,
                    "Original instance " + pair.getOriginalInstanceId()
                            + " and its forward replacement are no longer available.", now);
            return;
        }

        if (pair.getRollbackReplacementInstanceId() == null) {
            try {
                AsgInstance rollback = recoverRollbackReplacement(asg, pair).orElse(null);
                if (rollback == null) {
                    if (pair.getRollbackLaunchClientToken() == null) {
                        pair.setRollbackLaunchClientToken(
                                refresh.getInstanceRefreshId() + ":rollback:" + pair.getOriginalInstanceId());
                    }
                    pair.setRollbackPhase("Launching");
                    asgService.saveInstanceRefresh(refresh);
                    rollback = launchRollbackReplacement(asg, pair);
                }
                pair.setRollbackReplacementInstanceId(rollback.getInstanceId());
                pair.setRollbackPhase("Pending");
                pair.setRollbackReadyTime(null);
                updateRollbackProgress(refresh);
                asgService.saveInstanceRefresh(refresh);
            } catch (Exception e) {
                failInstanceRefreshRollback(asg, refresh, pair,
                        "Rollback replacement launch failed: " + message(e), now);
            }
            return;
        }

        AsgInstance rollback = findAsgInstance(asg, pair.getRollbackReplacementInstanceId()).orElse(null);
        if (rollback == null) {
            failInstanceRefreshRollback(asg, refresh, pair,
                    "Rollback replacement instance " + pair.getRollbackReplacementInstanceId()
                            + " failed before becoming ready.", now);
            return;
        }
        if (!"InService".equals(rollback.getLifecycleState())
                || !"Healthy".equals(rollback.getHealthStatus())) {
            pair.setRollbackReadyTime(null);
            pair.setRollbackPhase("Pending");
            asgService.saveInstanceRefresh(refresh);
            return;
        }
        TargetReadiness targetReadiness = targetReadiness(asg, rollback.getInstanceId());
        if (targetReadiness.failureReason() != null) {
            failInstanceRefreshRollback(asg, refresh, pair, targetReadiness.failureReason(), now);
            return;
        }
        if (!targetReadiness.ready()) {
            pair.setRollbackReadyTime(null);
            pair.setRollbackPhase("Pending");
            asgService.saveInstanceRefresh(refresh);
            return;
        }
        if (pair.getRollbackReadyTime() == null) {
            pair.setRollbackReadyTime(now);
            pair.setRollbackPhase("Warming");
            asgService.saveInstanceRefresh(refresh);
            return;
        }
        int warmupSeconds = refresh.getInstanceWarmup() != null ? refresh.getInstanceWarmup() : 0;
        if (Duration.between(pair.getRollbackReadyTime(), now).getSeconds() < warmupSeconds) {
            return;
        }

        try {
            terminateRollbackMember(asg, forward);
        } catch (Exception e) {
            String cleanupFailure = cleanupFailedRollbackReplacement(asg, rollback);
            String reason = "Failed to remove forward replacement " + forward.getInstanceId() + ": " + message(e);
            if (cleanupFailure != null) {
                reason += "; rollback replacement cleanup failed: " + cleanupFailure;
            }
            failInstanceRefreshRollback(asg, refresh, pair, reason, now);
            return;
        }
        pair.setRollbackPhase("Completed");
        pair.setRollbackFailureReason(null);
        updateRollbackProgress(refresh);
        asgService.saveAutoScalingGroup(asg);
        asgService.saveInstanceRefresh(refresh);
    }

    private AsgInstance launchRollbackReplacement(AutoScalingGroup asg, InstanceRefreshReplacement pair) {
        LaunchSource launchSource = rollbackLaunchSource(asg, pair);
        String az = pair.getOriginalAvailabilityZone() != null
                ? pair.getOriginalAvailabilityZone()
                : asg.getAvailabilityZones().isEmpty() ? asg.getRegion() + "a" : asg.getAvailabilityZones().getFirst();
        String subnetId = asg.getSubnetIds().isEmpty() ? null : asg.getSubnetIds().getFirst();
        Reservation reservation = ec2Service.runInstancesWithUserData(
                asg.getRegion(), launchSource.imageId(), launchSource.instanceType(), 1, 1,
                launchSource.keyName(), launchSource.securityGroupIds(), subnetId,
                pair.getRollbackLaunchClientToken(), propagatedInstanceTags(asg, launchSource),
                launchSource.userData(), launchSource.iamInstanceProfile());
        if (reservation.getInstances() == null || reservation.getInstances().size() != 1) {
            throw new IllegalStateException("Rollback launch did not return exactly one instance");
        }
        AsgInstance rollback = attachRefreshReplacement(asg, launchSource,
                reservation.getInstances().getFirst(), az, pair.getRollbackLaunchClientToken());
        rollback.setProtectedFromScaleIn(pair.isOriginalProtectedFromScaleIn());
        asgService.saveAutoScalingGroup(asg);
        return rollback;
    }

    private Optional<AsgInstance> recoverRollbackReplacement(AutoScalingGroup asg,
                                                             InstanceRefreshReplacement pair) {
        if (!"Launching".equals(pair.getRollbackPhase()) || pair.getRollbackLaunchClientToken() == null) {
            return Optional.empty();
        }
        Optional<AsgInstance> existingMember = asg.getInstances().stream()
                .filter(instance -> pair.getRollbackLaunchClientToken().equals(instance.getLaunchClientToken()))
                .findFirst();
        if (existingMember.isPresent()) {
            return existingMember;
        }
        LaunchSource launchSource = rollbackLaunchSource(asg, pair);
        return ec2Service.describeInstances(asg.getRegion(), List.of(), Map.of()).stream()
                .flatMap(reservation -> reservation.getInstances().stream())
                .filter(instance -> pair.getRollbackLaunchClientToken().equals(instance.getClientToken()))
                .findFirst()
                .map(instance -> {
                    AsgInstance recovered = attachRefreshReplacement(asg, launchSource, instance,
                            instance.getPlacement() != null ? instance.getPlacement().getAvailabilityZone()
                                    : pair.getOriginalAvailabilityZone(),
                            pair.getRollbackLaunchClientToken());
                    recovered.setProtectedFromScaleIn(pair.isOriginalProtectedFromScaleIn());
                    asgService.saveAutoScalingGroup(asg);
                    return recovered;
                });
    }

    private LaunchSource rollbackLaunchSource(AutoScalingGroup asg, InstanceRefreshReplacement pair) {
        AutoScalingGroup source = new AutoScalingGroup();
        source.setRegion(asg.getRegion());
        source.setAutoScalingGroupName(asg.getAutoScalingGroupName());
        source.setLaunchConfigurationName(pair.getOriginalLaunchConfigurationName());
        source.setLaunchTemplateId(pair.getOriginalLaunchTemplateId());
        source.setLaunchTemplateName(pair.getOriginalLaunchTemplateName());
        source.setLaunchTemplateVersion(pair.getOriginalLaunchTemplateVersion());
        LaunchSource launchSource = resolveLaunchSource(source);
        if (launchSource == null) {
            throw new IllegalStateException("No original launch source is available");
        }
        return launchSource;
    }

    private void terminateRollbackMember(AutoScalingGroup asg, AsgInstance member) {
        deregisterRefreshOriginal(asg, member.getInstanceId());
        ec2Service.terminateInstances(asg.getRegion(), List.of(member.getInstanceId()));
        asg.getInstances().remove(member);
    }

    private String cleanupFailedRollbackReplacement(AutoScalingGroup asg, AsgInstance rollback) {
        try {
            terminateRollbackMember(asg, rollback);
            asgService.saveAutoScalingGroup(asg);
            return null;
        } catch (Exception e) {
            return message(e);
        }
    }

    private void completeInstanceRefreshRollback(AutoScalingGroup asg, InstanceRefresh refresh, Instant now) {
        AutoScalingService.restoreSourceConfiguration(asg, refresh);
        refresh.setStatus("RollbackSuccessful");
        refresh.setPhase("Completed");
        refresh.setStatusReason("Instance refresh rollback completed.");
        refresh.setPercentageCompleteOnRollback(100);
        refresh.setInstancesToUpdateOnRollback(0);
        refresh.setEndTime(now);
        asgService.saveAutoScalingGroup(asg);
        asgService.saveInstanceRefresh(refresh);
    }

    private void failInstanceRefreshRollback(AutoScalingGroup asg, InstanceRefresh refresh,
                                             InstanceRefreshReplacement pair, String reason, Instant now) {
        AsgInstance rollback = findAsgInstance(asg, pair.getRollbackReplacementInstanceId()).orElse(null);
        if (rollback != null) {
            String cleanupFailure = cleanupFailedRollbackReplacement(asg, rollback);
            if (cleanupFailure == null) {
                pair.setRollbackReplacementInstanceId(null);
            } else {
                reason += "; rollback replacement cleanup failed: " + cleanupFailure;
            }
        }
        pair.setRollbackPhase("Failed");
        pair.setRollbackFailureReason(reason);
        refresh.setStatus("RollbackFailed");
        refresh.setPhase("Failed");
        refresh.setRollbackFailureReason(reason);
        refresh.setStatusReason("Instance refresh rollback failed: " + reason);
        refresh.setEndTime(now);
        updateRollbackProgress(refresh);
        asgService.saveAutoScalingGroup(asg);
        asgService.saveInstanceRefresh(refresh);
    }

    private static void updateRollbackProgress(InstanceRefresh refresh) {
        long completed = refresh.getReplacements().stream()
                .filter(replacement -> "Completed".equals(replacement.getRollbackPhase()))
                .count();
        int total = refresh.getReplacements().size();
        refresh.setInstancesToUpdateOnRollback(total - (int) completed);
        refresh.setPercentageCompleteOnRollback(total == 0 ? 100 : (int) (completed * 100 / total));
    }

    private static Optional<AsgInstance> findAsgInstance(AutoScalingGroup asg, String instanceId) {
        if (instanceId == null) {
            return Optional.empty();
        }
        return asg.getInstances().stream()
                .filter(instance -> instanceId.equals(instance.getInstanceId()))
                .findFirst();
    }

    private static Optional<AsgInstance> findForwardReplacement(AutoScalingGroup asg,
                                                                InstanceRefreshReplacement pair) {
        Optional<AsgInstance> byId = findAsgInstance(asg, pair.getReplacementInstanceId());
        if (byId.isPresent() || pair.getLaunchClientToken() == null) {
            return byId;
        }
        return asg.getInstances().stream()
                .filter(instance -> pair.getLaunchClientToken().equals(instance.getLaunchClientToken()))
                .findFirst();
    }

    private static void restoreOriginal(AsgInstance original) {
        if (original != null && "Standby".equals(original.getLifecycleState())) {
            original.setLifecycleState("InService");
        }
    }

    private static void updateRefreshProgress(InstanceRefresh refresh) {
        long completed = refresh.getReplacements().stream()
                .filter(replacement -> "Completed".equals(replacement.getPhase()))
                .count();
        int total = refresh.getReplacements().size();
        refresh.setInstancesToUpdate(total - (int) completed);
        refresh.setPercentageComplete(total == 0 ? 100 : (int) (completed * 100 / total));
    }

    private static String message(Exception exception) {
        return exception.getMessage() != null ? exception.getMessage() : exception.getClass().getSimpleName();
    }

    static long activeCapacity(AutoScalingGroup asg) {
        return asg.getInstances().stream()
                .filter(i -> {
                    String state = i.getLifecycleState();
                    return "Pending".equals(state) || "InService".equals(state);
                })
                .count();
    }

    private void promoteReadyInstances(AutoScalingGroup asg) {
        boolean changed = false;
        for (AsgInstance asgInst : asg.getInstances()) {
            if (!"Pending".equals(asgInst.getLifecycleState())) {
                continue;
            }
            try {
                List<Instance> ec2Instances = ec2Service
                        .describeInstances(asg.getRegion(), List.of(asgInst.getInstanceId()), null)
                        .stream().flatMap(r -> r.getInstances().stream()).collect(Collectors.toList());
                if (ec2Instances.isEmpty()) {
                    continue;
                }
                String ec2State = ec2Instances.get(0).getState().getName();
                if ("running".equals(ec2State)) {
                    asgInst.setLifecycleState("InService");
                    asgInst.setHealthStatus("Healthy");
                    registerWithTargetGroups(asg, asgInst);
                    changed = true;
                    asgService.recordActivity(asg.getRegion(), asg.getAutoScalingGroupName(),
                            "Launching a new EC2 instance: " + asgInst.getInstanceId(),
                            "An instance was started in response to a desired capacity change.",
                            "Successful");
                    LOG.infov("ASG {0}: instance {1} is now InService",
                            asg.getAutoScalingGroupName(), asgInst.getInstanceId());
                }
            } catch (Exception e) {
                LOG.debugv("ASG {0}: could not promote instance {1}: {2}",
                        asg.getAutoScalingGroupName(), asgInst.getInstanceId(), e.getMessage());
            }
        }
        if (changed) {
            asgService.saveAutoScalingGroup(asg);
        }
    }

    private List<String> removeStaleInstances(AutoScalingGroup asg) {
        List<AsgInstance> staleInstances = asg.getInstances().stream()
                .filter(instance -> isStaleInstance(asg, instance))
                .collect(Collectors.toList());
        if (staleInstances.isEmpty()) {
            return List.of();
        }

        List<String> instanceIds = staleInstances.stream()
                .map(AsgInstance::getInstanceId)
                .collect(Collectors.toList());
        failActiveSsmInvocations(asg, instanceIds);
        asg.getInstances().removeIf(instance -> instanceIds.contains(instance.getInstanceId()));
        asgService.saveAutoScalingGroup(asg);
        asgService.recordActivity(asg.getRegion(), asg.getAutoScalingGroupName(),
                "Removing stale EC2 instance reference(s): " + instanceIds,
                "Persisted Auto Scaling state referenced instance containers that are no longer running.",
                "Successful");
        LOG.infov("ASG {0}: removed stale instance reference(s) {1}",
                asg.getAutoScalingGroupName(), instanceIds);
        return instanceIds;
    }

    private void failActiveSsmInvocations(AutoScalingGroup asg, List<String> instanceIds) {
        if (ssmCommandService == null) {
            return;
        }
        int failed = ssmCommandService.failActiveInvocationsForInstances(
                asg.getRegion(),
                Set.copyOf(instanceIds),
                "Undeliverable");
        if (failed > 0) {
            LOG.infov("ASG {0}: marked {1} active SSM command invocation(s) failed for stale instances {2}",
                    asg.getAutoScalingGroupName(), failed, instanceIds);
        }
    }

    private boolean isStaleInstance(AutoScalingGroup asg, AsgInstance instance) {
        String lifecycleState = instance.getLifecycleState();
        if ("InService".equals(lifecycleState)) {
            return !ec2Service.isInstanceContainerRunning(instance.getInstanceId());
        }
        if ("Pending".equals(lifecycleState)) {
            return isMissingOrTerminalEc2Instance(asg, instance);
        }
        return false;
    }

    private boolean isMissingOrTerminalEc2Instance(AutoScalingGroup asg, AsgInstance instance) {
        try {
            List<Instance> ec2Instances = ec2Service
                    .describeInstances(asg.getRegion(), List.of(instance.getInstanceId()), null)
                    .stream()
                    .flatMap(r -> r.getInstances().stream())
                    .collect(Collectors.toList());
            if (ec2Instances.isEmpty()) {
                return true;
            }
            String state = ec2Instances.getFirst().getState() != null
                    ? ec2Instances.getFirst().getState().getName()
                    : null;
            return "shutting-down".equals(state)
                    || "terminated".equals(state)
                    || "stopping".equals(state)
                    || "stopped".equals(state);
        }
        catch (Exception e) {
            LOG.debugv("ASG {0}: keeping pending instance {1} during stale check: {2}",
                    asg.getAutoScalingGroupName(), instance.getInstanceId(), e.getMessage());
            return false;
        }
    }

    private void reconcileActiveTargetRegistrations(AutoScalingGroup asg) {
        List<String> inServiceInstanceIds = asg.getInstances().stream()
                .filter(instance -> "InService".equals(instance.getLifecycleState()))
                .map(AsgInstance::getInstanceId)
                .filter(id -> id != null)
                .distinct()
                .toList();
        if (inServiceInstanceIds.isEmpty() || asg.getTargetGroupARNs().isEmpty()) {
            return;
        }

        for (String tgArn : asg.getTargetGroupARNs()) {
            try {
                TargetGroup targetGroup = elbV2Service.describeTargetGroups(
                        asg.getRegion(), null, List.of(tgArn), List.of()).getFirst();
                int effectivePort = ElbV2HealthChecker.effectivePort(new TargetDescription(), targetGroup);
                Set<String> registeredInstanceIds = elbV2Service.describeTargetHealth(
                                asg.getRegion(), tgArn, List.of()).stream()
                        .map(TargetHealth::getTarget)
                        .filter(target -> target != null && target.getId() != null)
                        .filter(target -> ElbV2HealthChecker.effectivePort(target, targetGroup) == effectivePort)
                        .map(TargetDescription::getId)
                        .collect(Collectors.toSet());
                List<TargetDescription> missingTargets = inServiceInstanceIds.stream()
                        .filter(instanceId -> !registeredInstanceIds.contains(instanceId))
                        .map(instanceId -> target(instanceId, effectivePort))
                        .toList();
                if (!missingTargets.isEmpty()) {
                    elbV2Service.registerTargets(asg.getRegion(), tgArn, missingTargets);
                    LOG.infov("ASG {0}: registered missing target(s) {1} with TG {2} on port {3}",
                            asg.getAutoScalingGroupName(),
                            missingTargets.stream().map(TargetDescription::getId).toList(),
                            tgArn,
                            effectivePort);
                }
            } catch (Exception e) {
                LOG.warnv("ASG {0}: could not heal target registrations for TG {1}: {2}",
                        asg.getAutoScalingGroupName(), tgArn, e.getMessage());
            }
        }
    }

    private static TargetDescription target(String instanceId, int port) {
        TargetDescription target = new TargetDescription();
        target.setId(instanceId);
        target.setPort(port);
        return target;
    }

    private void removeTerminatingInstances(AutoScalingGroup asg) {
        List<AsgInstance> terminatingInstances = asg.getInstances().stream()
                .filter(instance -> "Terminating".equals(instance.getLifecycleState()))
                .collect(Collectors.toList());
        if (terminatingInstances.isEmpty()) {
            return;
        }

        List<String> instanceIds = terminatingInstances.stream()
                .map(AsgInstance::getInstanceId)
                .collect(Collectors.toList());
        deregisterFromTargetGroups(asg, instanceIds);
        try {
            ec2Service.terminateInstances(asg.getRegion(), instanceIds);
        } catch (Exception e) {
            LOG.warnv("ASG {0}: failed to terminate refreshing instances {1}: {2}",
                    asg.getAutoScalingGroupName(), instanceIds, e.getMessage());
            return;
        }

        asg.getInstances().removeIf(instance -> instanceIds.contains(instance.getInstanceId()));
        asgService.saveAutoScalingGroup(asg);
        asgService.recordActivity(asg.getRegion(), asg.getAutoScalingGroupName(),
                "Terminating EC2 instance(s) for refresh: " + instanceIds,
                "An instance refresh requested replacement of active instances.",
                "Successful");
        LOG.infov("ASG {0}: terminated instance(s) for refresh {1}",
                asg.getAutoScalingGroupName(), instanceIds);
    }

    private void scaleOut(AutoScalingGroup asg, int count) {
        LaunchSource launchSource = resolveLaunchSource(asg);
        if (launchSource == null) {
            LOG.warnv("ASG {0}: no launch source found, cannot scale out", asg.getAutoScalingGroupName());
            return;
        }
        LOG.infov("ASG {0}: scaling out by {1}", asg.getAutoScalingGroupName(), count);
        String az = asg.getAvailabilityZones().isEmpty()
                ? asg.getRegion() + "a"
                : asg.getAvailabilityZones().get(0);
        String subnetId = asg.getSubnetIds().isEmpty() ? null : asg.getSubnetIds().get(0);
        try {
            Reservation reservation = ec2Service.runInstancesWithUserData(
                    asg.getRegion(),
                    launchSource.imageId(),
                    launchSource.instanceType(),
                    count, count,
                    launchSource.keyName(),
                    launchSource.securityGroupIds(),
                    subnetId,
                    null,
                    propagatedInstanceTags(asg, launchSource),
                    launchSource.userData(),
                    launchSource.iamInstanceProfile());

            for (Instance ec2Inst : reservation.getInstances()) {
                AsgInstance asgInst = new AsgInstance();
                asgInst.setInstanceId(ec2Inst.getInstanceId());
                asgInst.setAvailabilityZone(az);
                asgInst.setLifecycleState("Pending");
                asgInst.setHealthStatus("Healthy");
                asgInst.setLaunchConfigurationName(launchSource.launchConfigurationName());
                asgInst.setLaunchTemplateId(launchSource.launchTemplateId());
                asgInst.setLaunchTemplateName(launchSource.launchTemplateName());
                asgInst.setLaunchTemplateVersion(launchSource.launchTemplateVersion());
                asgInst.setInstanceType(launchSource.instanceType());
                asg.getInstances().add(asgInst);
                LOG.infov("ASG {0}: launched instance {1} (Pending)",
                        asg.getAutoScalingGroupName(), ec2Inst.getInstanceId());
            }
            asgService.saveAutoScalingGroup(asg);
        } catch (Exception e) {
            LOG.warnv("ASG {0}: failed to launch instances: {1}",
                    asg.getAutoScalingGroupName(), e.getMessage());
        }
    }

    private static List<io.github.hectorvent.floci.services.ec2.model.Tag> propagatedInstanceTags(
            AutoScalingGroup asg,
            LaunchSource launchSource) {
        Map<String, String> tags = new LinkedHashMap<>();
        for (io.github.hectorvent.floci.services.ec2.model.Tag tag : launchSource.instanceTags()) {
            tags.put(tag.getKey(), tag.getValue());
        }
        asg.getTags().forEach((key, value) -> {
            if (asg.getTagPropagateAtLaunch().getOrDefault(key, false)) {
                tags.put(key, value);
            }
        });
        return tags.entrySet().stream()
                .map(entry -> new io.github.hectorvent.floci.services.ec2.model.Tag(entry.getKey(), entry.getValue()))
                .toList();
    }

    private void scaleIn(AutoScalingGroup asg, int count) {
        List<AsgInstance> candidates = asg.getInstances().stream()
                .filter(i -> "InService".equals(i.getLifecycleState()))
                .filter(i -> !i.isProtectedFromScaleIn())
                .collect(Collectors.toList());

        List<AsgInstance> toTerminate = candidates.subList(0, Math.min(count, candidates.size()));
        if (toTerminate.isEmpty()) {
            return;
        }
        LOG.infov("ASG {0}: scaling in {1} instance(s)", asg.getAutoScalingGroupName(), toTerminate.size());

        List<String> instanceIds = toTerminate.stream()
                .map(AsgInstance::getInstanceId)
                .collect(Collectors.toList());

        deregisterFromTargetGroups(asg, instanceIds);

        try {
            ec2Service.terminateInstances(asg.getRegion(), instanceIds);
        } catch (Exception e) {
            LOG.warnv("ASG {0}: failed to terminate instances {1}: {2}",
                    asg.getAutoScalingGroupName(), instanceIds, e.getMessage());
            return;
        }

        asg.getInstances().removeIf(i -> instanceIds.contains(i.getInstanceId()));
        asgService.saveAutoScalingGroup(asg);
        asgService.recordActivity(asg.getRegion(), asg.getAutoScalingGroupName(),
                "Terminating EC2 instance(s): " + instanceIds,
                "An instance was terminated in response to a desired capacity change.",
                "Successful");
    }

    private void deregisterFromTargetGroups(AutoScalingGroup asg, List<String> instanceIds) {
        for (String tgArn : asg.getTargetGroupARNs()) {
            try {
                List<TargetDescription> targets = instanceIds.stream()
                        .map(id -> { TargetDescription td = new TargetDescription(); td.setId(id); return td; })
                        .collect(Collectors.toList());
                elbV2Service.deregisterTargets(asg.getRegion(), tgArn, targets);
            } catch (Exception e) {
                LOG.debugv("ASG {0}: could not deregister from TG {1}: {2}",
                        asg.getAutoScalingGroupName(), tgArn, e.getMessage());
            }
        }
    }

    private void deregisterRefreshOriginal(AutoScalingGroup asg, String instanceId) {
        TargetDescription target = new TargetDescription();
        target.setId(instanceId);
        for (String targetGroupArn : asg.getTargetGroupARNs()) {
            elbV2Service.deregisterTargets(asg.getRegion(), targetGroupArn, List.of(target));
        }
    }

    private void registerWithTargetGroups(AutoScalingGroup asg, AsgInstance asgInst) {
        for (String tgArn : asg.getTargetGroupARNs()) {
            try {
                TargetDescription td = new TargetDescription();
                td.setId(asgInst.getInstanceId());
                elbV2Service.registerTargets(asg.getRegion(), tgArn, List.of(td));
                LOG.debugv("ASG {0}: registered {1} with TG {2}",
                        asg.getAutoScalingGroupName(), asgInst.getInstanceId(), tgArn);
            } catch (Exception e) {
                LOG.warnv("ASG {0}: could not register {1} with TG {2}: {3}",
                        asg.getAutoScalingGroupName(), asgInst.getInstanceId(), tgArn, e.getMessage());
            }
        }
    }

    private LaunchSource resolveLaunchSource(AutoScalingGroup asg) {
        LaunchConfiguration lc = resolveLaunchConfiguration(asg);
        if (lc != null) {
            return new LaunchSource(
                    lc.getLaunchConfigurationName(),
                    lc.getImageId(),
                    lc.getInstanceType(),
                    lc.getKeyName(),
                    lc.getSecurityGroups(),
                    List.of(),
                    Ec2UserData.fromEncoded(lc.getUserData()),
                    lc.getIamInstanceProfile(),
                    null,
                    null,
                    null);
        }

        LaunchTemplate launchTemplate = resolveLaunchTemplate(asg);
        if (launchTemplate != null) {
            LaunchTemplate version = ec2Service.describeLaunchTemplateVersions(
                    asg.getRegion(),
                    launchTemplate.getLaunchTemplateId(),
                    null,
                    asg.getLaunchTemplateVersion() == null ? List.of() : List.of(asg.getLaunchTemplateVersion()))
                    .getFirst();
            String resolvedVersion = version.getLatestVersionNumber() != null
                    ? version.getLatestVersionNumber()
                    : asg.getLaunchTemplateVersion();
            return new LaunchSource(
                    null,
                    version.getImageId(),
                    version.getInstanceType(),
                    version.getKeyName(),
                    version.getSecurityGroupIds(),
                    version.getInstanceTags(),
                    Ec2UserData.fromEncoded(version.getEncodedUserData()),
                    version.getIamInstanceProfileArn(),
                    asg.getLaunchTemplateId(),
                    asg.getLaunchTemplateName(),
                    resolvedVersion);
        }

        MixedInstancesPolicy.LaunchTemplateSpecification specification =
                mixedInstancesLaunchTemplateSpecification(asg);
        if (specification != null) {
            LaunchTemplate mixedLaunchTemplate = resolveMixedInstancesLaunchTemplate(asg, specification);
            if (mixedLaunchTemplate != null) {
                LaunchTemplate version = ec2Service.describeLaunchTemplateVersions(
                        asg.getRegion(),
                        mixedLaunchTemplate.getLaunchTemplateId(),
                        null,
                        specification.getVersion() == null ? List.of() : List.of(specification.getVersion()))
                        .getFirst();
                String resolvedVersion = version.getLatestVersionNumber() != null
                        ? version.getLatestVersionNumber()
                        : specification.getVersion();
                String instanceType = mixedInstancesInstanceType(asg, version);
                return new LaunchSource(
                        null,
                        version.getImageId(),
                        instanceType,
                        version.getKeyName(),
                        version.getSecurityGroupIds(),
                        version.getInstanceTags(),
                        Ec2UserData.fromEncoded(version.getEncodedUserData()),
                        version.getIamInstanceProfileArn(),
                        specification.getLaunchTemplateId() == null
                                ? mixedLaunchTemplate.getLaunchTemplateId()
                                : specification.getLaunchTemplateId(),
                        specification.getLaunchTemplateName(),
                        resolvedVersion);
            }
        }

        return null;
    }

    private LaunchConfiguration resolveLaunchConfiguration(AutoScalingGroup asg) {
        String lcName = asg.getLaunchConfigurationName();
        if (lcName == null || lcName.isBlank()) {
            return null;
        }
        List<LaunchConfiguration> lcs = asgService.describeLaunchConfigurations(
                asg.getRegion(), List.of(lcName));
        return lcs.isEmpty() ? null : lcs.get(0);
    }

    private LaunchTemplate resolveLaunchTemplate(AutoScalingGroup asg) {
        String ltId = asg.getLaunchTemplateId();
        String ltName = asg.getLaunchTemplateName();
        if ((ltId == null || ltId.isBlank()) && (ltName == null || ltName.isBlank())) {
            return null;
        }
        List<LaunchTemplate> launchTemplates = ec2Service.describeLaunchTemplates(
                asg.getRegion(),
                ltId == null || ltId.isBlank() ? List.of() : List.of(ltId),
                ltName == null || ltName.isBlank() ? List.of() : List.of(ltName),
                Map.of());
        return launchTemplates.isEmpty() ? null : launchTemplates.get(0);
    }

    private MixedInstancesPolicy.LaunchTemplateSpecification mixedInstancesLaunchTemplateSpecification(
            AutoScalingGroup asg) {
        MixedInstancesPolicy policy = asg.getMixedInstancesPolicy();
        if (policy == null || policy.getLaunchTemplate() == null) {
            return null;
        }
        MixedInstancesPolicy.LaunchTemplateSpecification specification =
                policy.getLaunchTemplate().getLaunchTemplateSpecification();
        if (specification == null) {
            return null;
        }
        String ltId = specification.getLaunchTemplateId();
        String ltName = specification.getLaunchTemplateName();
        if ((ltId == null || ltId.isBlank()) && (ltName == null || ltName.isBlank())) {
            return null;
        }
        return specification;
    }

    private LaunchTemplate resolveMixedInstancesLaunchTemplate(
            AutoScalingGroup asg, MixedInstancesPolicy.LaunchTemplateSpecification specification) {
        String ltId = specification.getLaunchTemplateId();
        String ltName = specification.getLaunchTemplateName();
        List<LaunchTemplate> launchTemplates = ec2Service.describeLaunchTemplates(
                asg.getRegion(),
                ltId == null || ltId.isBlank() ? List.of() : List.of(ltId),
                ltName == null || ltName.isBlank() ? List.of() : List.of(ltName),
                Map.of());
        return launchTemplates.isEmpty() ? null : launchTemplates.get(0);
    }

    private String mixedInstancesInstanceType(AutoScalingGroup asg, LaunchTemplate version) {
        MixedInstancesPolicy policy = asg.getMixedInstancesPolicy();
        if (policy != null && policy.getLaunchTemplate() != null) {
            List<MixedInstancesPolicy.LaunchTemplateOverride> overrides =
                    policy.getLaunchTemplate().getOverrides();
            if (overrides != null) {
                for (MixedInstancesPolicy.LaunchTemplateOverride override : overrides) {
                    if (override.getInstanceType() != null && !override.getInstanceType().isBlank()) {
                        return override.getInstanceType();
                    }
                }
            }
        }
        return version.getInstanceType();
    }

    private record LaunchSource(
            String launchConfigurationName,
            String imageId,
            String instanceType,
            String keyName,
            List<String> securityGroupIds,
            List<io.github.hectorvent.floci.services.ec2.model.Tag> instanceTags,
            Ec2UserData userData,
            String iamInstanceProfile,
            String launchTemplateId,
            String launchTemplateName,
            String launchTemplateVersion) {}

    private record TargetReadiness(boolean ready, String failureReason) {
        private static TargetReadiness satisfied() { return new TargetReadiness(true, null); }
        private static TargetReadiness pending() { return new TargetReadiness(false, null); }
        private static TargetReadiness failure(String reason) { return new TargetReadiness(false, reason); }
    }

    // Override for describeAutoScalingGroups with null region (all regions)
    // The service only filters by region when non-null; null means all.
    // We add a bridge here to avoid changing the service signature.
}
