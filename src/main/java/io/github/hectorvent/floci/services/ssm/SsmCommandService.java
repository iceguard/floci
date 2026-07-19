package io.github.hectorvent.floci.services.ssm;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.Resettable;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.services.ssm.model.Command;
import io.github.hectorvent.floci.services.ssm.model.CommandInvocation;
import io.github.hectorvent.floci.services.ssm.model.InstanceInformation;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Handles SSM agent registration and command execution lifecycle:
 * - UpdateInstanceInformation (agent side, via AmazonSSM target)
 * - SendCommand / GetCommandInvocation / ListCommands / ListCommandInvocations / CancelCommand (public API)
 * - GetMessages / AcknowledgeMessage / SendReply / FailMessage / DeleteMessage (ec2messages, agent side)
 */
@ApplicationScoped
public class SsmCommandService implements Resettable {

    private static final Logger LOG = Logger.getLogger(SsmCommandService.class);
    private static final int MIN_TIMEOUT_SECONDS = 30;
    private static final int MAX_TIMEOUT_SECONDS = 2_592_000;
    private static final int MAX_STDOUT_CHARS = 24000;
    private static final int MAX_STDERR_CHARS = 8000;

    private final StorageBackend<String, InstanceInformation> instanceStore;
    private final StorageBackend<String, Command> commandStore;
    private final StorageBackend<String, CommandInvocation> invocationStore;
    private final ObjectMapper objectMapper;
    private final RegionResolver regionResolver;
    private final SsmDirectCommandExecutor directCommandExecutor;
    private volatile ExecutorService directExecutionExecutor;
    private final AtomicLong directExecutionGeneration = new AtomicLong();
    private final Set<String> locallyOwnedDirectExecutions = ConcurrentHashMap.newKeySet();

    @Inject
    public SsmCommandService(
            StorageFactory storageFactory,
            ObjectMapper objectMapper,
            RegionResolver regionResolver,
            SsmDirectCommandExecutor directCommandExecutor) {
        this.instanceStore = storageFactory.create("ssm", "ssm-instances.json", new TypeReference<>() {});
        this.commandStore = storageFactory.create("ssm", "ssm-commands.json", new TypeReference<>() {});
        this.invocationStore = storageFactory.create("ssm", "ssm-invocations.json", new TypeReference<>() {});
        this.objectMapper = objectMapper;
        this.regionResolver = regionResolver;
        this.directCommandExecutor = directCommandExecutor;
        this.directExecutionExecutor = newDirectExecutionExecutor();
    }

    private static ExecutorService newDirectExecutionExecutor() {
        return Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "floci-ssm-direct-execution");
            thread.setDaemon(true);
            return thread;
        });
    }

    @Override
    public void clear() {
        stopDirectExecutionWorkers(true);
    }

    void shutdown() {
        stopDirectExecutionWorkers(false);
    }

    private void stopDirectExecutionWorkers(boolean restart) {
        List<SsmDirectCommandExecutor.ExecutionIdentity> activeExecutions = new ArrayList<>();
        ExecutorService executor;
        synchronized (this) {
            directExecutionGeneration.incrementAndGet();
            for (StoredInvocation stored : allInvocations()) {
                CommandInvocation invocation = stored.invocation();
                hydrateAccountId(invocation, stored.accountId());
                if (invocation.isDirectExecution() && invocation.getDirectExecId() != null
                        && isActiveInvocation(invocation.getStatus())) {
                    activeExecutions.add(executionIdentity(invocation));
                }
            }
            executor = directExecutionExecutor;
            locallyOwnedDirectExecutions.clear();
            if (restart) {
                directExecutionExecutor = newDirectExecutionExecutor();
            }
        }
        activeExecutions.forEach(directCommandExecutor::stopExecution);
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                LOG.warn("SSM direct-execution workers did not terminate within 5 seconds");
            }
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ── Agent registration ──────────────────────────────────────────────────

    public void updateInstanceInformation(JsonNode request, String region) {
        String instanceId = request.path("InstanceId").asText("");
        if (instanceId.isEmpty()) {
            // Some older agent versions don't send InstanceId; fall back to a generated key
            instanceId = "mi-" + UUID.randomUUID().toString().replace("-", "").substring(0, 17);
        }

        InstanceInformation info = instanceStore.get(instanceKey(region, instanceId))
                .orElse(new InstanceInformation());

        info.setInstanceId(instanceId);
        info.setAgentName(request.path("AgentName").asText("amazon-ssm-agent"));
        info.setAgentVersion(request.path("AgentVersion").asText("3.0.0.0"));
        info.setPingStatus("Online");
        info.setLastPingDateTime(Instant.now());
        info.setPlatformType(request.path("PlatformType").asText("Linux"));
        info.setPlatformName(request.path("PlatformName").asText(""));
        info.setPlatformVersion(request.path("PlatformVersion").asText(""));
        info.setIpAddress(request.path("IPAddress").asText(""));
        info.setComputerName(request.path("Hostname").asText(instanceId));
        info.setRegion(region);

        if (info.getRegistrationDate() == null) {
            info.setRegistrationDate(Instant.now());
        }

        instanceStore.put(instanceKey(region, instanceId), info);
        LOG.infov("SSM agent registered: instanceId={0} platform={1}/{2}", instanceId, info.getPlatformType(), info.getPlatformName());
    }

    public List<InstanceInformation> describeInstanceInformation(String region) {
        String prefix = region + "::";
        return instanceStore.scan(k -> k.startsWith(prefix));
    }

    // ── Public SendCommand API ──────────────────────────────────────────────

    public Command sendCommand(JsonNode request, String region) {
        String documentName = request.path("DocumentName").asText();
        if (documentName.isEmpty()) {
            throw new AwsException("InvalidDocument", "DocumentName is required.", 400);
        }

        List<String> instanceIds = new ArrayList<>();
        request.path("InstanceIds").forEach(n -> instanceIds.add(n.asText()));
        if (instanceIds.isEmpty()) {
            throw new AwsException("InvalidInstanceId", "At least one InstanceId is required.", 400);
        }

        Map<String, List<String>> parameters = parseParameters(request.get("Parameters"));
        int executionTimeoutSeconds = executionTimeoutSeconds(documentName, parameters);
        String comment = request.path("Comment").asText("");
        int timeoutSeconds = parseTimeoutSeconds(request.get("TimeoutSeconds"));
        String documentVersion = request.path("DocumentVersion").asText("$DEFAULT");
        String outputS3Bucket = request.path("OutputS3BucketName").asText("");
        String outputS3Prefix = request.path("OutputS3KeyPrefix").asText("");

        String commandId = UUID.randomUUID().toString();
        String accountId = regionResolver.getAccountId();
        Instant now = Instant.now();
        List<DirectExecutionRequest> directExecutionRequests = new ArrayList<>();

        Command command = new Command();
        command.setCommandId(commandId);
        command.setDocumentName(documentName);
        command.setDocumentVersion(documentVersion);
        command.setComment(comment);
        command.setParameters(parameters);
        command.setInstanceIds(new ArrayList<>(instanceIds));
        command.setRequestedDateTime(now);
        command.setStatus("Pending");
        command.setStatusDetails(statusDetails("Pending"));
        command.setTimeoutSeconds(timeoutSeconds);
        command.setExecutionTimeoutSeconds(executionTimeoutSeconds);
        command.setTargetCount(instanceIds.size());
        command.setOutputS3BucketName(outputS3Bucket.isEmpty() ? null : outputS3Bucket);
        command.setOutputS3KeyPrefix(outputS3Prefix.isEmpty() ? null : outputS3Prefix);
        command.setOutputS3Region(region);
        command.setRegion(region);
        command.setAccountId(accountId);
        command.setExpiresAfter(now.plusSeconds((long) timeoutSeconds + executionTimeoutSeconds));

        command.setStatus("InProgress");
        command.setStatusDetails(statusDetails("InProgress"));
        putCommand(command);

        // Create invocations and queue messages or directly execute against Floci EC2 containers.
        for (String instanceId : instanceIds) {
            CommandInvocation inv = new CommandInvocation();
            inv.setCommandId(commandId);
            inv.setInstanceId(instanceId);
            inv.setComment(comment);
            inv.setDocumentName(documentName);
            inv.setDocumentVersion(documentVersion);
            inv.setRequestedDateTime(now);
            inv.setStatus("Pending");
            inv.setStatusDetails(statusDetails("Pending"));
            inv.setRegion(region);
            inv.setAccountId(accountId);
            inv.setExecutionTimeoutSeconds(executionTimeoutSeconds);
            inv.setDeliveryDeadline(now.plusSeconds((long) timeoutSeconds + executionTimeoutSeconds));

            if (directCommandExecutor.supports(instanceId, documentName)) {
                inv.setDirectExecution(true);
                putInvocation(inv);
                directExecutionRequests.add(new DirectExecutionRequest(instanceId, documentName, parameters));
            }
            else {
                prepareMessage(inv, documentName, parameters, timeoutSeconds, region);
                putInvocation(inv);
            }
        }

        LOG.infov("SendCommand: commandId={0} document={1} targets={2}", commandId, documentName, instanceIds);
        Command response = copyCommand(command);
        for (DirectExecutionRequest directExecutionRequest : directExecutionRequests) {
            runDirectCommandAsync(
                    commandId,
                    directExecutionRequest.instanceId(),
                    directExecutionRequest.documentName(),
                    directExecutionRequest.parameters(),
                    executionTimeoutSeconds,
                    region,
                    accountId);
        }
        return response;
    }

    private static int parseTimeoutSeconds(JsonNode node) {
        if (node == null || node.isNull()) {
            return 3_600;
        }
        if (!node.isIntegralNumber() || !node.canConvertToInt()) {
            throw timeoutValidation(node.toString(), "an integer");
        }
        int timeoutSeconds = node.intValue();
        if (timeoutSeconds < MIN_TIMEOUT_SECONDS) {
            throw new AwsException(
                    "ValidationException",
                    "1 validation error detected: Value '" + timeoutSeconds + "' at 'timeoutSeconds' failed to satisfy constraint: Member must have value greater than or equal to 30",
                    400);
        }
        if (timeoutSeconds > MAX_TIMEOUT_SECONDS) {
            throw new AwsException(
                    "ValidationException",
                    "1 validation error detected: Value '" + timeoutSeconds + "' at 'timeoutSeconds' failed to satisfy constraint: Member must have value less than or equal to 2592000",
                    400);
        }
        return timeoutSeconds;
    }

    private static AwsException timeoutValidation(String value, String constraint) {
        return new AwsException(
                "ValidationException",
                "1 validation error detected: Value '" + value + "' at 'timeoutSeconds' failed to satisfy constraint: Member must be " + constraint,
                400);
    }

    private static int executionTimeoutSeconds(String documentName, Map<String, List<String>> parameters) {
        if (!"AWS-RunShellScript".equals(documentName)) {
            return SsmDirectCommandExecutor.DEFAULT_EXECUTION_TIMEOUT_SECONDS;
        }
        try {
            return SsmDirectCommandExecutor.executionTimeoutSeconds(parameters);
        }
        catch (IllegalArgumentException e) {
            throw new AwsException(
                    "InvalidParameters",
                    "Parameter executionTimeout is not valid for document " + documentName
                            + ". The value must be an integer from 1 to 172800.",
                    400);
        }
    }

    public CommandInvocation getCommandInvocation(String commandId, String instanceId, String region) {
        return invocationStore.get(invocationKey(region, commandId, instanceId))
                .orElseThrow(() -> new AwsException("InvocationDoesNotExist",
                        "Command " + commandId + " on instance " + instanceId + " does not exist.", 400));
    }

    public List<Command> listCommands(String commandId, String instanceId, String region) {
        expireInvocations(Instant.now());
        String prefix = region + "::";
        return commandStore.scan(k -> {
            if (!k.startsWith(prefix)) return false;
            if (commandId != null && !k.equals(commandKey(region, commandId))) return false;
            if (instanceId != null) {
                Command cmd = commandStore.get(k).orElse(null);
                return cmd != null && cmd.getInstanceIds() != null && cmd.getInstanceIds().contains(instanceId);
            }
            return true;
        });
    }

    public List<CommandInvocation> listCommandInvocations(String commandId, String instanceId, String region) {
        expireInvocations(Instant.now());
        String prefix = region + "::";
        return invocationStore.scan(k -> {
            if (!k.startsWith(prefix)) return false;
            if (commandId != null && !k.contains("::" + commandId + "::")) return false;
            if (instanceId != null && !k.endsWith("::" + instanceId)) return false;
            return true;
        });
    }

    public synchronized void cancelCommand(String commandId, List<String> targetInstanceIds, String region) {
        Command command = commandStore.get(commandKey(region, commandId))
                .orElseThrow(() -> new AwsException("InvalidCommandId",
                        "Command " + commandId + " does not exist.", 400));

        List<String> targets = (targetInstanceIds != null && !targetInstanceIds.isEmpty())
                ? targetInstanceIds
                : command.getInstanceIds();

        for (String instanceId : targets) {
            String invKey = invocationKey(region, commandId, instanceId);
            invocationStore.get(invKey).ifPresent(inv -> {
                if (isActiveInvocation(inv.getStatus())) {
                    inv.setStatus("Cancelled");
                    inv.setStatusDetails("Cancelled");
                    inv.setMessagePayload(null);
                    if (inv.isDirectExecution() && inv.getDirectExecId() != null) {
                        directCommandExecutor.stopExecution(executionIdentity(inv));
                    }
                    invocationStore.put(invKey, inv);
                }
            });
        }

        command.setStatus("Cancelled");
        command.setStatusDetails("Cancelled");
        commandStore.put(commandKey(region, commandId), command);
        LOG.infov("CancelCommand: commandId={0}", commandId);
    }

    public int failActiveInvocationsForInstance(String region, String instanceId, String statusDetails) {
        return failActiveInvocationsForInstances(region, Set.of(instanceId), statusDetails);
    }

    public synchronized int failActiveInvocationsForInstances(
            String region, Set<String> instanceIds, String statusDetails) {
        if (instanceIds == null || instanceIds.isEmpty()) {
            return 0;
        }
        String prefix = region + "::";
        Instant now = Instant.now();
        Set<String> commandIds = new LinkedHashSet<>();
        int failed = 0;

        for (CommandInvocation invocation : invocationStore.scan(key -> key.startsWith(prefix))) {
            if (!instanceIds.contains(invocation.getInstanceId())) {
                continue;
            }
            if (!isActiveInvocation(invocation.getStatus())) {
                continue;
            }
            invocation.setStatus("Failed");
            invocation.setStatusDetails(statusDetails);
            invocation.setResponseCode(-1);
            invocation.setExecutionEndDateTime(now);
            invocationStore.put(invocationKey(region, invocation.getCommandId(), invocation.getInstanceId()), invocation);
            commandIds.add(invocation.getCommandId());
            failed++;
        }

        commandIds.forEach(commandId -> updateCommandStatus(commandId, region));
        return failed;
    }

    // ── ec2messages agent protocol ──────────────────────────────────────────

    public synchronized List<Map<String, Object>> getMessages(
            String instanceId, String messagesRequestId, int visibilityTimeout) {
        Instant now = Instant.now();
        expireInvocations(now);
        CommandInvocation invocation = invocationStore.scan(key -> key.endsWith("::" + instanceId)).stream()
                .filter(inv -> "Pending".equals(inv.getStatus()))
                .filter(inv -> inv.getMessagePayload() != null)
                .filter(inv -> inv.getMessageVisibleAfter() == null || !inv.getMessageVisibleAfter().isAfter(now))
                .findFirst()
                .orElse(null);
        if (invocation == null) {
            return List.of();
        }
        invocation.setMessageVisibleAfter(now.plusSeconds(Math.max(0, visibilityTimeout)));
        invocationStore.put(invocationKey(
                invocation.getRegion(), invocation.getCommandId(), invocation.getInstanceId()), invocation);

        LOG.infov("GetMessages: instanceId={0} returned messageId={1}", instanceId, invocation.getMessageId());
        return List.of(Map.of(
                "MessageId", invocation.getMessageId(),
                "Destination", instanceId,
                "CreatedDate", invocation.getMessageCreatedDate().toString(),
                "Topic", "aws.ssm.sendCommand." + invocation.getRegion(),
                "Payload", invocation.getMessagePayload()));
    }

    public synchronized void acknowledgeMessage(String messageId) {
        findInvocationByMessageId(messageId).ifPresent(inv -> {
            if (!"Pending".equals(inv.getStatus())) {
                return;
            }
            Instant now = Instant.now();
            inv.setStatus("InProgress");
            inv.setStatusDetails(statusDetails("InProgress"));
            inv.setExecutionStartDateTime(now);
            inv.setExecutionDeadline(now.plusSeconds(inv.getExecutionTimeoutSeconds()));
            inv.setMessageAcknowledged(true);
            putInvocation(inv);
            LOG.debugv("AcknowledgeMessage: messageId={0} commandId={1}", messageId, inv.getCommandId());
        });
    }

    public synchronized void sendReply(String messageId, String payloadBase64) {
        CommandInvocation existing = findInvocationByMessageId(messageId).orElse(null);
        if (existing == null) {
            LOG.warnv("SendReply: unknown messageId={0}", messageId);
            return;
        }
        String commandId = existing.getCommandId();
        String instanceId = existing.getInstanceId();
        String region = existing.getRegion();
        String accountId = existing.getAccountId();

        try {
            byte[] decoded = Base64.getDecoder().decode(payloadBase64);
            JsonNode payload = objectMapper.readTree(decoded);

            String status = "Success";
            int returnCode = 0;
            String stdout = "";
            String stderr = "";
            Instant endTime = Instant.now();

            // Parse runtimeStatus or pluginResults — take the first plugin entry found
            JsonNode statusNode = payload.has("runtimeStatus") ? payload.get("runtimeStatus")
                    : payload.get("pluginResults");
            if (statusNode != null && statusNode.isObject()) {
                Iterator<Map.Entry<String, JsonNode>> it = statusNode.fields();
                if (it.hasNext()) {
                    JsonNode plugin = it.next().getValue();
                    status = plugin.path("status").asText("Success");
                    returnCode = plugin.path("returnCode").asInt(plugin.path("code").asInt(0));
                    stdout = plugin.path("standardOutput").asText(plugin.path("output").asText(""));
                    stderr = plugin.path("standardError").asText("");
                }
            }

            // Trim output to AWS limits
            if (stdout.length() > MAX_STDOUT_CHARS) {
                stdout = truncateOutput(stdout, MAX_STDOUT_CHARS);
            }
            if (stderr.length() > MAX_STDERR_CHARS) {
                stderr = truncateOutput(stderr, MAX_STDERR_CHARS);
            }

            String invKey = invocationKey(region, commandId, instanceId);
            CommandInvocation inv = getInvocation(accountId, invKey).orElse(null);
            if (inv != null && isActiveInvocation(inv.getStatus())) {
                inv.setStatus(toInvocationStatus(status));
                inv.setStatusDetails(statusDetails(toInvocationStatus(status)));
                inv.setStandardOutputContent(stdout);
                inv.setStandardErrorContent(stderr);
                inv.setResponseCode(returnCode);
                inv.setExecutionEndDateTime(endTime);
                inv.setMessagePayload(null);
                putInvocation(inv);
            }

            // Recalculate command status
            updateCommandStatus(commandId, region, accountId);
            LOG.infov("SendReply: commandId={0} instanceId={1} status={2} rc={3}", commandId, instanceId, status, returnCode);
        } catch (Exception e) {
            LOG.warnv(e, "Failed to parse SendReply payload for messageId={0}", messageId);
        }
    }

    public synchronized void failMessage(String messageId, String failureType) {
        CommandInvocation existing = findInvocationByMessageId(messageId).orElse(null);
        if (existing == null) {
            return;
        }
        String commandId = existing.getCommandId();
        String instanceId = existing.getInstanceId();
        String region = existing.getRegion();
        String accountId = existing.getAccountId();

        String invKey = invocationKey(region, commandId, instanceId);
        getInvocation(accountId, invKey).ifPresent(inv -> {
            if (!isActiveInvocation(inv.getStatus())) {
                return;
            }
            inv.setStatus("Failed");
            inv.setStatusDetails("Failed: " + failureType);
            inv.setExecutionEndDateTime(Instant.now());
            putInvocation(inv);
        });
        updateCommandStatus(commandId, region, accountId);
        LOG.warnv("FailMessage: commandId={0} instanceId={1} failureType={2}", commandId, instanceId, failureType);
    }

    public synchronized void deleteMessage(String messageId) {
        findInvocationByMessageId(messageId).ifPresent(inv -> {
            inv.setMessagePayload(null);
            putInvocation(inv);
        });
    }

    // ── CodeDeploy integration helpers ─────────────────────────────────────

    public boolean isInstanceRegistered(String instanceId, String region) {
        return instanceStore.get(instanceKey(region, instanceId)).isPresent();
    }

    public String sendCommandToInstance(String instanceId, String documentName,
                                        Map<String, List<String>> parameters,
                                        int timeoutSeconds, String region) {
        if (timeoutSeconds < MIN_TIMEOUT_SECONDS || timeoutSeconds > MAX_TIMEOUT_SECONDS) {
            throw new IllegalArgumentException("timeoutSeconds must be from 30 to 2592000");
        }
        int executionTimeoutSeconds = executionTimeoutSeconds(documentName, parameters);
        String commandId = UUID.randomUUID().toString();
        String accountId = regionResolver.getAccountId();
        Instant now = Instant.now();

        Command command = new Command();
        command.setCommandId(commandId);
        command.setDocumentName(documentName);
        command.setDocumentVersion("$DEFAULT");
        command.setParameters(parameters);
        command.setInstanceIds(List.of(instanceId));
        command.setRequestedDateTime(now);
        command.setStatus("InProgress");
        command.setStatusDetails(statusDetails("InProgress"));
        command.setTimeoutSeconds(timeoutSeconds);
        command.setExecutionTimeoutSeconds(executionTimeoutSeconds);
        command.setTargetCount(1);
        command.setRegion(region);
        command.setAccountId(accountId);
        command.setExpiresAfter(now.plusSeconds((long) timeoutSeconds + executionTimeoutSeconds));
        putCommand(command);

        CommandInvocation inv = new CommandInvocation();
        inv.setCommandId(commandId);
        inv.setInstanceId(instanceId);
        inv.setDocumentName(documentName);
        inv.setDocumentVersion("$DEFAULT");
        inv.setRequestedDateTime(now);
        inv.setStatus("Pending");
        inv.setStatusDetails(statusDetails("Pending"));
        inv.setRegion(region);
        inv.setAccountId(accountId);
        inv.setExecutionTimeoutSeconds(executionTimeoutSeconds);
        inv.setDeliveryDeadline(now.plusSeconds((long) timeoutSeconds + executionTimeoutSeconds));
        prepareMessage(inv, documentName, parameters, timeoutSeconds, region);
        putInvocation(inv);

        return commandId;
    }

    public String getCommandInvocationStatus(String commandId, String instanceId, String region) {
        return invocationStore.get(invocationKey(region, commandId, instanceId))
                .map(CommandInvocation::getStatus)
                .orElse("Failed");
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    private void runDirectCommandAsync(
            String commandId,
            String instanceId,
            String documentName,
            Map<String, List<String>> parameters,
            int executionTimeoutSeconds,
            String region,
            String accountId) {
        long generation = directExecutionGeneration.get();
        ExecutorService executor = directExecutionExecutor;
        CompletableFuture.runAsync(() -> {
            String invKey = invocationKey(region, commandId, instanceId);
            String executionKey = directExecutionKey(accountId, invKey);
            if (!isCurrentDirectExecutionGeneration(generation)) {
                return;
            }
            CommandInvocation invocation = getInvocation(accountId, invKey).orElse(null);
            if (invocation == null || !isActiveInvocation(invocation.getStatus())) {
                return;
            }

            SsmDirectCommandExecutor.ExecutionResult result;
            try {
                result = directCommandExecutor
                        .executeIfSupported(instanceId, documentName, parameters, executionTimeoutSeconds, identity -> {
                            synchronized (this) {
                                if (!isCurrentDirectExecutionGeneration(generation)) {
                                    directCommandExecutor.stopExecution(identity);
                                    throw new IllegalStateException("SSM direct execution was reset");
                                }
                                CommandInvocation current = getInvocation(accountId, invKey).orElse(null);
                                if (current == null || !isActiveInvocation(current.getStatus())) {
                                    throw new IllegalStateException(
                                            "SSM invocation became terminal before Docker exec start");
                                }
                                current.setStatus("InProgress");
                                current.setStatusDetails(statusDetails("InProgress"));
                                current.setDirectContainerId(identity.containerId());
                                current.setDirectExecId(identity.execId());
                                current.setDirectRuntimeFile(identity.runtimeFile());
                                current.setExecutionStartDateTime(identity.startedAt());
                                current.setExecutionDeadline(identity.deadline());
                                locallyOwnedDirectExecutions.add(executionKey);
                                putInvocation(current);
                            }
                        })
                        .orElse(null);
                synchronized (this) {
                    if (!isCurrentDirectExecutionGeneration(generation)) {
                        return;
                    }
                    invocation = getInvocation(accountId, invKey).orElse(null);
                    if (invocation == null || !isActiveInvocation(invocation.getStatus())) {
                        return;
                    }
                    if (result == null) {
                        invocation.setStatus("Pending");
                        invocation.setStatusDetails(statusDetails("Pending"));
                        invocation.setDirectExecution(false);
                        prepareMessage(invocation, documentName, parameters,
                                Math.toIntExact(java.time.Duration.between(
                                        invocation.getRequestedDateTime(), invocation.getDeliveryDeadline()).getSeconds()),
                                region);
                        putInvocation(invocation);
                        updateCommandStatus(commandId, region, accountId);
                        return;
                    }
                    if ("InProgress".equals(result.status())) {
                        return;
                    }
                    applyDirectResult(invocation, result);
                    putInvocation(invocation);
                    updateCommandStatus(commandId, region, accountId);
                }
            }
            finally {
                locallyOwnedDirectExecutions.remove(executionKey);
            }
        }, executor);
    }

    private boolean isCurrentDirectExecutionGeneration(long generation) {
        return generation == directExecutionGeneration.get();
    }

    private void applyDirectResult(CommandInvocation invocation, SsmDirectCommandExecutor.ExecutionResult result) {
        invocation.setStatus(result.status());
        invocation.setStatusDetails(statusDetails(result.status()));
        invocation.setStandardOutputContent(truncateOutput(result.standardOutput(), MAX_STDOUT_CHARS));
        invocation.setStandardErrorContent(truncateOutput(result.standardError(), MAX_STDERR_CHARS));
        invocation.setResponseCode(result.responseCode());
        invocation.setExecutionStartDateTime(result.executionStartDateTime());
        invocation.setExecutionEndDateTime(result.executionEndDateTime());
        invocation.setDirectExecId(null);
        invocation.setDirectRuntimeFile(null);
    }

    private static String truncateOutput(String output, int maxChars) {
        if (output == null) {
            return "";
        }
        if (output.length() <= maxChars) {
            return output;
        }
        return output.substring(0, maxChars);
    }

    private void prepareMessage(CommandInvocation invocation, String documentName,
                                Map<String, List<String>> parameters, int timeoutSeconds, String region) {
        String messageId = UUID.randomUUID().toString();
        invocation.setMessageId(messageId);
        invocation.setMessagePayload(buildCommandPayload(
                invocation.getCommandId(), documentName, documentVersion(parameters), parameters, timeoutSeconds, region));
        invocation.setMessageCreatedDate(Instant.now());
        invocation.setMessageVisibleAfter(null);
        invocation.setMessageAcknowledged(false);
    }

    private String buildCommandPayload(String commandId, String documentName, String docVersion,
                                       Map<String, List<String>> parameters, int timeoutSeconds, String region) {
        try {
            ObjectNode payload = objectMapper.createObjectNode();
            payload.put("DocumentName", documentName);
            payload.put("DocumentVersion", docVersion);
            payload.put("CommandId", commandId);
            payload.put("OutputS3BucketName", "");
            payload.put("OutputS3KeyPrefix", "");
            payload.put("OutputS3Region", region);
            payload.put("CloudWatchLogGroupName", "");
            payload.put("CloudWatchLogStreamName", "");

            ObjectNode params = objectMapper.createObjectNode();
            if (parameters != null) {
                for (Map.Entry<String, List<String>> e : parameters.entrySet()) {
                    ArrayNode arr = objectMapper.createArrayNode();
                    e.getValue().forEach(arr::add);
                    params.set(e.getKey(), arr);
                }
            }
            payload.set("Parameters", params);
            payload.set("DocumentContent", buildDocumentContent(documentName));

            return Base64.getEncoder().encodeToString(objectMapper.writeValueAsBytes(payload));
        } catch (Exception e) {
            throw new RuntimeException("Failed to build command payload", e);
        }
    }

    private JsonNode buildDocumentContent(String documentName) {
        ObjectNode doc = objectMapper.createObjectNode();
        doc.put("schemaVersion", "2.2");
        doc.put("description", documentName);

        ObjectNode docParams = objectMapper.createObjectNode();
        ObjectNode commandsParam = objectMapper.createObjectNode();
        commandsParam.put("type", "StringList");
        commandsParam.put("description", "Commands to run.");
        docParams.set("commands", commandsParam);

        ObjectNode wdParam = objectMapper.createObjectNode();
        wdParam.put("type", "String");
        wdParam.put("default", "");
        wdParam.put("description", "Working directory.");
        docParams.set("workingDirectory", wdParam);

        ObjectNode toParam = objectMapper.createObjectNode();
        toParam.put("type", "String");
        toParam.put("default", String.valueOf(SsmDirectCommandExecutor.DEFAULT_EXECUTION_TIMEOUT_SECONDS));
        toParam.put("description", "Execution timeout in seconds.");
        docParams.set("executionTimeout", toParam);
        doc.set("parameters", docParams);

        ArrayNode mainSteps = objectMapper.createArrayNode();
        ObjectNode step = objectMapper.createObjectNode();
        step.put("action", resolveAction(documentName));
        step.put("name", "runShellScript");
        ObjectNode inputs = objectMapper.createObjectNode();
        inputs.put("runCommand", "{{ commands }}");
        inputs.put("workingDirectory", "{{ workingDirectory }}");
        inputs.put("timeoutSeconds", "{{ executionTimeout }}");
        step.set("inputs", inputs);
        mainSteps.add(step);
        doc.set("mainSteps", mainSteps);

        return doc;
    }

    private String resolveAction(String documentName) {
        return switch (documentName) {
            case "AWS-RunPowerShellScript" -> "aws:runPowerShellScript";
            default -> "aws:runShellScript";
        };
    }

    private String documentVersion(Map<String, List<String>> parameters) {
        return "$DEFAULT";
    }

    private void updateCommandStatus(String commandId, String region) {
        updateCommandStatus(commandId, region, regionResolver.getAccountId());
    }

    private void updateCommandStatus(String commandId, String region, String accountId) {
        Command command = getCommand(accountId, commandKey(region, commandId)).orElse(null);
        if (command == null) {
            return;
        }
        if (command.getAccountId() == null) {
            command.setAccountId(accountId);
        }

        List<String> instanceIds = command.getInstanceIds();
        int completed = 0;
        int errors = 0;
        int unsuccessful = 0;
        int timedOut = 0;
        int deliveryTimedOut = 0;
        boolean anyInProgress = false;

        for (String iid : instanceIds) {
            CommandInvocation inv = getInvocation(accountId, invocationKey(region, commandId, iid)).orElse(null);
            if (inv == null) continue;
            String s = inv.getStatus();
            if ("Success".equals(s)) {
                completed++;
            } else if ("Failed".equals(s) || "TimedOut".equals(s) || "Cancelled".equals(s)) {
                completed++;
                unsuccessful++;
                if ("Failed".equals(s)
                        || ("TimedOut".equals(s) && "Execution Timed Out".equals(inv.getStatusDetails()))) {
                    errors++;
                }
                if ("TimedOut".equals(s)) {
                    timedOut++;
                    if ("Delivery Timed Out".equals(inv.getStatusDetails())) {
                        deliveryTimedOut++;
                    }
                }
            } else if ("InProgress".equals(s) || "Pending".equals(s)) {
                anyInProgress = true;
            }
        }

        command.setCompletedCount(completed);
        command.setErrorCount(errors);
        command.setDeliveryTimedOutCount(deliveryTimedOut);

        if (!anyInProgress && completed == instanceIds.size()) {
            String status = commandStatus(unsuccessful, timedOut, instanceIds.size());
            command.setStatus(status);
            command.setStatusDetails("TimedOut".equals(status) && deliveryTimedOut == instanceIds.size()
                    ? "Delivery Timed Out"
                    : statusDetails(status));
        }

        putCommand(command);
    }

    private static String commandStatus(int errors, int timedOut, int targetCount) {
        if (errors == 0) {
            return "Success";
        }
        if (timedOut == targetCount) {
            return "TimedOut";
        }
        if (errors == targetCount) {
            return "Failed";
        }
        return "Success";
    }

    private static String toInvocationStatus(String agentStatus) {
        return switch (agentStatus) {
            case "Success" -> "Success";
            case "Failed" -> "Failed";
            case "TimedOut" -> "TimedOut";
            case "Cancelled", "Canceled" -> "Cancelled";
            default -> "Failed";
        };
    }

    private static boolean isActiveInvocation(String status) {
        return "Pending".equals(status) || "InProgress".equals(status);
    }

    synchronized void restorePersistedLifecycle() {
        Instant now = Instant.now();
        Set<CommandReference> commands = new LinkedHashSet<>();
        for (StoredInvocation stored : allInvocations()) {
            CommandInvocation invocation = stored.invocation();
            if (hydrateAccountId(invocation, stored.accountId())) {
                putInvocation(invocation);
            }
            commands.add(new CommandReference(
                    invocation.getCommandId(), invocation.getRegion(), stored.accountId()));
            if (!isActiveInvocation(invocation.getStatus())) {
                continue;
            }
            if (invocation.isDirectExecution() && invocation.getDirectExecId() != null) {
                reconcileDirectExecution(invocation, now);
            }
        }
        expireInvocations(now);
        for (CommandReference command : commands) {
            updateCommandStatus(command.commandId(), command.region(), command.accountId());
        }
    }

    synchronized void expireInvocations(Instant now) {
        Set<CommandReference> changedCommands = new LinkedHashSet<>();
        for (StoredInvocation stored : allInvocations()) {
            CommandInvocation invocation = stored.invocation();
            if (hydrateAccountId(invocation, stored.accountId())) {
                putInvocation(invocation);
            }
            if (!isActiveInvocation(invocation.getStatus())) {
                continue;
            }
            if ("Pending".equals(invocation.getStatus())
                    && invocation.getDeliveryDeadline() != null
                    && !now.isBefore(invocation.getDeliveryDeadline())) {
                completeTimeout(invocation, "Delivery Timed Out", now);
                changedCommands.add(new CommandReference(
                        invocation.getCommandId(), invocation.getRegion(), invocation.getAccountId()));
                continue;
            }
            if ("InProgress".equals(invocation.getStatus())
                    && invocation.getExecutionDeadline() != null
                    && !now.isBefore(invocation.getExecutionDeadline())) {
                if (invocation.isDirectExecution() && invocation.getDirectExecId() != null
                        && !directCommandExecutor.stopExecution(executionIdentity(invocation))) {
                    LOG.warnv("SSM execution {0} could not be stopped at its deadline; retaining InProgress",
                            invocation.getDirectExecId());
                    continue;
                }
                completeTimeout(invocation, "Execution Timed Out", now);
                changedCommands.add(new CommandReference(
                        invocation.getCommandId(), invocation.getRegion(), invocation.getAccountId()));
            }
        }
        for (CommandReference changed : changedCommands) {
            updateCommandStatus(changed.commandId(), changed.region(), changed.accountId());
        }
    }

    private void reconcileDirectExecution(CommandInvocation invocation, Instant now) {
        if (locallyOwnedDirectExecutions.contains(directExecutionKey(
                invocation.getAccountId(), invocationKey(
                        invocation.getRegion(), invocation.getCommandId(), invocation.getInstanceId())))) {
            return;
        }
        SsmDirectCommandExecutor.ExecutionIdentity identity = executionIdentity(invocation);
        SsmDirectCommandExecutor.ExecutionState state = directCommandExecutor.inspectExecution(identity);
        if (state == SsmDirectCommandExecutor.ExecutionState.RUNNING) {
            if (invocation.getExecutionDeadline() != null && !now.isBefore(invocation.getExecutionDeadline())) {
                expireInvocations(now);
            }
            return;
        }
        if (state == SsmDirectCommandExecutor.ExecutionState.FINISHED) {
            Optional<SsmDirectCommandExecutor.ExecutionResult> recovered =
                    directCommandExecutor.recoverFinishedExecution(identity);
            if (recovered.isPresent() && isActiveInvocation(invocation.getStatus())) {
                applyDirectResult(invocation, recovered.get());
                putInvocation(invocation);
                updateCommandStatus(invocation.getCommandId(), invocation.getRegion(), invocation.getAccountId());
            }
            return;
        }
        if (invocation.getExecutionDeadline() != null && !now.isBefore(invocation.getExecutionDeadline())) {
            if (invocation.getDirectExecId() != null && !directCommandExecutor.stopExecution(identity)) {
                LOG.warnv("SSM execution {0} could not be stopped after reconciliation; retaining InProgress",
                        invocation.getDirectExecId());
                return;
            }
            completeTimeout(invocation, "Execution Timed Out", now);
            updateCommandStatus(invocation.getCommandId(), invocation.getRegion(), invocation.getAccountId());
        }
    }

    private void completeTimeout(CommandInvocation invocation, String details, Instant now) {
        if (!isActiveInvocation(invocation.getStatus())) {
            return;
        }
        invocation.setStatus("TimedOut");
        invocation.setStatusDetails(details);
        invocation.setResponseCode(-1);
        invocation.setExecutionEndDateTime(now);
        invocation.setMessagePayload(null);
        invocation.setDirectExecId(null);
        invocation.setDirectRuntimeFile(null);
        putInvocation(invocation);
    }

    private Optional<CommandInvocation> findInvocationByMessageId(String messageId) {
        return invocationStore.scan(key -> true).stream()
                .filter(invocation -> messageId.equals(invocation.getMessageId()))
                .findFirst();
    }

    private void putInvocation(CommandInvocation invocation) {
        String key = invocationKey(invocation.getRegion(), invocation.getCommandId(), invocation.getInstanceId());
        if (invocationStore instanceof AccountAwareStorageBackend<CommandInvocation> accountAware
                && invocation.getAccountId() != null) {
            accountAware.putForAccount(invocation.getAccountId(), key, invocation);
        }
        else {
            invocationStore.put(key, invocation);
        }
    }

    private Optional<CommandInvocation> getInvocation(String accountId, String key) {
        if (invocationStore instanceof AccountAwareStorageBackend<CommandInvocation> accountAware
                && accountId != null) {
            return accountAware.getForAccount(accountId, key);
        }
        return invocationStore.get(key);
    }

    private List<StoredInvocation> allInvocations() {
        if (invocationStore instanceof AccountAwareStorageBackend<CommandInvocation> accountAware) {
            return accountAware.scanAllAccountEntries().stream()
                    .map(entry -> new StoredInvocation(entry.accountId(), entry.key(), entry.value()))
                    .toList();
        }
        return invocationStore.keys().stream()
                .map(key -> invocationStore.get(key)
                        .map(invocation -> new StoredInvocation(invocation.getAccountId(), key, invocation))
                        .orElse(null))
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    private Optional<Command> getCommand(String accountId, String key) {
        if (commandStore instanceof AccountAwareStorageBackend<Command> accountAware && accountId != null) {
            return accountAware.getForAccount(accountId, key);
        }
        return commandStore.get(key);
    }

    private void putCommand(Command command) {
        String key = commandKey(command.getRegion(), command.getCommandId());
        if (commandStore instanceof AccountAwareStorageBackend<Command> accountAware
                && command.getAccountId() != null) {
            accountAware.putForAccount(command.getAccountId(), key, command);
        }
        else {
            commandStore.put(key, command);
        }
    }

    private static SsmDirectCommandExecutor.ExecutionIdentity executionIdentity(CommandInvocation invocation) {
        return new SsmDirectCommandExecutor.ExecutionIdentity(
                invocation.getDirectContainerId(),
                invocation.getDirectExecId(),
                invocation.getDirectRuntimeFile(),
                invocation.getExecutionStartDateTime(),
                invocation.getExecutionDeadline());
    }

    private static String statusDetails(String status) {
        return switch (status) {
            case "InProgress" -> "In Progress";
            case "TimedOut" -> "Execution Timed Out";
            default -> status;
        };
    }

    private static Command copyCommand(Command source) {
        Command copy = new Command();
        copy.setCommandId(source.getCommandId());
        copy.setDocumentName(source.getDocumentName());
        copy.setDocumentVersion(source.getDocumentVersion());
        copy.setComment(source.getComment());
        copy.setExpiresAfter(source.getExpiresAfter());
        copy.setParameters(source.getParameters());
        copy.setInstanceIds(source.getInstanceIds() == null ? null : new ArrayList<>(source.getInstanceIds()));
        copy.setRequestedDateTime(source.getRequestedDateTime());
        copy.setStatus(source.getStatus());
        copy.setStatusDetails(source.getStatusDetails());
        copy.setTimeoutSeconds(source.getTimeoutSeconds());
        copy.setExecutionTimeoutSeconds(source.getExecutionTimeoutSeconds());
        copy.setTargetCount(source.getTargetCount());
        copy.setCompletedCount(source.getCompletedCount());
        copy.setErrorCount(source.getErrorCount());
        copy.setDeliveryTimedOutCount(source.getDeliveryTimedOutCount());
        copy.setOutputS3BucketName(source.getOutputS3BucketName());
        copy.setOutputS3KeyPrefix(source.getOutputS3KeyPrefix());
        copy.setOutputS3Region(source.getOutputS3Region());
        copy.setRegion(source.getRegion());
        copy.setAccountId(source.getAccountId());
        return copy;
    }

    private record DirectExecutionRequest(
            String instanceId,
            String documentName,
            Map<String, List<String>> parameters) {}

    private record CommandReference(String commandId, String region, String accountId) {}

    private record StoredInvocation(String accountId, String key, CommandInvocation invocation) {}

    private static boolean hydrateAccountId(CommandInvocation invocation, String accountId) {
        if (invocation.getAccountId() == null) {
            invocation.setAccountId(accountId);
            return true;
        }
        return false;
    }

    private Map<String, List<String>> parseParameters(JsonNode parametersNode) {
        if (parametersNode == null || parametersNode.isNull()) {
            return Map.of();
        }
        if (!parametersNode.isObject()) {
            throw invalidParameters("Parameters must be an object whose values are string arrays.");
        }
        Map<String, List<String>> result = new java.util.LinkedHashMap<>();
        parametersNode.fields().forEachRemaining(entry -> {
            JsonNode value = entry.getValue();
            if (!value.isArray()) {
                throw invalidParameters("Parameter " + entry.getKey() + " must be a string array.");
            }
            List<String> values = new ArrayList<>();
            value.forEach(element -> {
                if (!element.isTextual()) {
                    throw invalidParameters("Parameter " + entry.getKey() + " must contain only strings.");
                }
                values.add(element.textValue());
            });
            result.put(entry.getKey(), List.copyOf(values));
        });
        return Map.copyOf(result);
    }

    private static AwsException invalidParameters(String message) {
        return new AwsException("InvalidParameters", message, 400);
    }

    private static String instanceKey(String region, String instanceId) {
        return region + "::" + instanceId;
    }

    private static String commandKey(String region, String commandId) {
        return region + "::" + commandId;
    }

    private static String invocationKey(String region, String commandId, String instanceId) {
        return region + "::" + commandId + "::" + instanceId;
    }

    private static String directExecutionKey(String accountId, String invocationKey) {
        return String.valueOf(accountId) + "::" + invocationKey;
    }

}
