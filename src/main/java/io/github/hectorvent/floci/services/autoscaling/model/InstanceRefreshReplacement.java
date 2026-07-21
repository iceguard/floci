package io.github.hectorvent.floci.services.autoscaling.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class InstanceRefreshReplacement {

    private String originalInstanceId;
    private String replacementInstanceId;
    private String launchClientToken;
    private String phase;
    private Instant readyTime;
    private String failureReason;
    private String originalLaunchConfigurationName;
    private String originalLaunchTemplateId;
    private String originalLaunchTemplateName;
    private String originalLaunchTemplateVersion;
    private String originalInstanceType;
    private String originalAvailabilityZone;
    private boolean originalProtectedFromScaleIn;
    private String rollbackReplacementInstanceId;
    private String rollbackLaunchClientToken;
    private String rollbackPhase;
    private Instant rollbackReadyTime;
    private String rollbackFailureReason;

    public InstanceRefreshReplacement() {}

    public String getOriginalInstanceId() { return originalInstanceId; }
    public void setOriginalInstanceId(String v) { this.originalInstanceId = v; }

    public String getReplacementInstanceId() { return replacementInstanceId; }
    public void setReplacementInstanceId(String v) { this.replacementInstanceId = v; }

    public String getLaunchClientToken() { return launchClientToken; }
    public void setLaunchClientToken(String v) { this.launchClientToken = v; }

    public String getPhase() { return phase; }
    public void setPhase(String v) { this.phase = v; }

    public Instant getReadyTime() { return readyTime; }
    public void setReadyTime(Instant v) { this.readyTime = v; }

    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String v) { this.failureReason = v; }

    public String getOriginalLaunchConfigurationName() { return originalLaunchConfigurationName; }
    public void setOriginalLaunchConfigurationName(String v) { this.originalLaunchConfigurationName = v; }

    public String getOriginalLaunchTemplateId() { return originalLaunchTemplateId; }
    public void setOriginalLaunchTemplateId(String v) { this.originalLaunchTemplateId = v; }

    public String getOriginalLaunchTemplateName() { return originalLaunchTemplateName; }
    public void setOriginalLaunchTemplateName(String v) { this.originalLaunchTemplateName = v; }

    public String getOriginalLaunchTemplateVersion() { return originalLaunchTemplateVersion; }
    public void setOriginalLaunchTemplateVersion(String v) { this.originalLaunchTemplateVersion = v; }

    public String getOriginalInstanceType() { return originalInstanceType; }
    public void setOriginalInstanceType(String v) { this.originalInstanceType = v; }

    public String getOriginalAvailabilityZone() { return originalAvailabilityZone; }
    public void setOriginalAvailabilityZone(String v) { this.originalAvailabilityZone = v; }

    public boolean isOriginalProtectedFromScaleIn() { return originalProtectedFromScaleIn; }
    public void setOriginalProtectedFromScaleIn(boolean v) { this.originalProtectedFromScaleIn = v; }

    public String getRollbackReplacementInstanceId() { return rollbackReplacementInstanceId; }
    public void setRollbackReplacementInstanceId(String v) { this.rollbackReplacementInstanceId = v; }

    public String getRollbackLaunchClientToken() { return rollbackLaunchClientToken; }
    public void setRollbackLaunchClientToken(String v) { this.rollbackLaunchClientToken = v; }

    public String getRollbackPhase() { return rollbackPhase; }
    public void setRollbackPhase(String v) { this.rollbackPhase = v; }

    public Instant getRollbackReadyTime() { return rollbackReadyTime; }
    public void setRollbackReadyTime(Instant v) { this.rollbackReadyTime = v; }

    public String getRollbackFailureReason() { return rollbackFailureReason; }
    public void setRollbackFailureReason(String v) { this.rollbackFailureReason = v; }
}
