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
}
