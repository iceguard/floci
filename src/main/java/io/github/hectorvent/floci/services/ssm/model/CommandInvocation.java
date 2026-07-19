package io.github.hectorvent.floci.services.ssm.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class CommandInvocation {

    private String commandId;
    private String instanceId;
    private String comment;
    private String documentName;
    private String documentVersion;
    private Instant requestedDateTime;
    private String status = "Pending";
    private String statusDetails = "Pending";
    private String standardOutputContent = "";
    private String standardErrorContent = "";
    private int responseCode = -1;
    private Instant executionStartDateTime;
    private Instant executionEndDateTime;
    private int executionTimeoutSeconds = 3600;
    private Instant deliveryDeadline;
    private Instant executionDeadline;
    private String messageId;
    private String messagePayload;
    private Instant messageCreatedDate;
    private Instant messageVisibleAfter;
    private boolean messageAcknowledged;
    private boolean directExecution;
    private String directContainerId;
    private String directExecId;
    private String directRuntimeFile;
    private String region;
    private String accountId;

    public CommandInvocation() {}

    public String getCommandId() { return commandId; }
    public void setCommandId(String commandId) { this.commandId = commandId; }

    public String getInstanceId() { return instanceId; }
    public void setInstanceId(String instanceId) { this.instanceId = instanceId; }

    public String getComment() { return comment; }
    public void setComment(String comment) { this.comment = comment; }

    public String getDocumentName() { return documentName; }
    public void setDocumentName(String documentName) { this.documentName = documentName; }

    public String getDocumentVersion() { return documentVersion; }
    public void setDocumentVersion(String documentVersion) { this.documentVersion = documentVersion; }

    public Instant getRequestedDateTime() { return requestedDateTime; }
    public void setRequestedDateTime(Instant requestedDateTime) { this.requestedDateTime = requestedDateTime; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getStatusDetails() { return statusDetails; }
    public void setStatusDetails(String statusDetails) { this.statusDetails = statusDetails; }

    public String getStandardOutputContent() { return standardOutputContent; }
    public void setStandardOutputContent(String standardOutputContent) { this.standardOutputContent = standardOutputContent; }

    public String getStandardErrorContent() { return standardErrorContent; }
    public void setStandardErrorContent(String standardErrorContent) { this.standardErrorContent = standardErrorContent; }

    public int getResponseCode() { return responseCode; }
    public void setResponseCode(int responseCode) { this.responseCode = responseCode; }

    public Instant getExecutionStartDateTime() { return executionStartDateTime; }
    public void setExecutionStartDateTime(Instant executionStartDateTime) { this.executionStartDateTime = executionStartDateTime; }

    public Instant getExecutionEndDateTime() { return executionEndDateTime; }
    public void setExecutionEndDateTime(Instant executionEndDateTime) { this.executionEndDateTime = executionEndDateTime; }

    public int getExecutionTimeoutSeconds() { return executionTimeoutSeconds; }
    public void setExecutionTimeoutSeconds(int executionTimeoutSeconds) { this.executionTimeoutSeconds = executionTimeoutSeconds; }

    public Instant getDeliveryDeadline() { return deliveryDeadline; }
    public void setDeliveryDeadline(Instant deliveryDeadline) { this.deliveryDeadline = deliveryDeadline; }

    public Instant getExecutionDeadline() { return executionDeadline; }
    public void setExecutionDeadline(Instant executionDeadline) { this.executionDeadline = executionDeadline; }

    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }

    public String getMessagePayload() { return messagePayload; }
    public void setMessagePayload(String messagePayload) { this.messagePayload = messagePayload; }

    public Instant getMessageCreatedDate() { return messageCreatedDate; }
    public void setMessageCreatedDate(Instant messageCreatedDate) { this.messageCreatedDate = messageCreatedDate; }

    public Instant getMessageVisibleAfter() { return messageVisibleAfter; }
    public void setMessageVisibleAfter(Instant messageVisibleAfter) { this.messageVisibleAfter = messageVisibleAfter; }

    public boolean isMessageAcknowledged() { return messageAcknowledged; }
    public void setMessageAcknowledged(boolean messageAcknowledged) { this.messageAcknowledged = messageAcknowledged; }

    public boolean isDirectExecution() { return directExecution; }
    public void setDirectExecution(boolean directExecution) { this.directExecution = directExecution; }

    public String getDirectContainerId() { return directContainerId; }
    public void setDirectContainerId(String directContainerId) { this.directContainerId = directContainerId; }

    public String getDirectExecId() { return directExecId; }
    public void setDirectExecId(String directExecId) { this.directExecId = directExecId; }

    public String getDirectRuntimeFile() { return directRuntimeFile; }
    public void setDirectRuntimeFile(String directRuntimeFile) { this.directRuntimeFile = directRuntimeFile; }

    public String getRegion() { return region; }
    public void setRegion(String region) { this.region = region; }

    public String getAccountId() { return accountId; }
    public void setAccountId(String accountId) { this.accountId = accountId; }
}
