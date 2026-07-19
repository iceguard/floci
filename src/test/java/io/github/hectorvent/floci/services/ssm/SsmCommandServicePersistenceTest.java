package io.github.hectorvent.floci.services.ssm;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.ssm.model.Command;
import io.github.hectorvent.floci.services.ssm.model.CommandInvocation;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SsmCommandServicePersistenceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RegionResolver regionResolver = mock(RegionResolver.class);

    @Test
    void pendingDeliverySurvivesServiceRecreationAndVisibilityTimeout() throws Exception {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmDirectCommandExecutor executor = mock(SsmDirectCommandExecutor.class);
        SsmCommandService first = service(storage, executor);

        Command command = first.sendCommand(request("i-agent", 60, "90"), "us-west-2");
        SsmCommandService restarted = service(storage, executor);
        restarted.restorePersistedLifecycle();

        List<Map<String, Object>> messages = restarted.getMessages("i-agent", "request-1", 30);
        assertEquals(1, messages.size());
        assertTrue(restarted.getMessages("i-agent", "request-2", 30).isEmpty());
        CommandInvocation invocation = restarted.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2");
        assertEquals(messages.getFirst().get("MessageId"), invocation.getMessageId());
        assertNotNull(invocation.getMessageVisibleAfter());
    }

    @Test
    void deliveryAndExecutionTimeoutsAreDistinctAndCounted() throws Exception {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmDirectCommandExecutor executor = mock(SsmDirectCommandExecutor.class);
        SsmCommandService service = service(storage, executor);
        Command command = service.sendCommand(request("i-agent", 30, "90"), "us-west-2");
        CommandInvocation invocation = service.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2");

        assertEquals(90, command.getExecutionTimeoutSeconds());
        assertEquals(Duration.ofSeconds(120),
                Duration.between(command.getRequestedDateTime(), command.getExpiresAfter()));
        assertEquals(Duration.ofSeconds(120),
                Duration.between(invocation.getRequestedDateTime(), invocation.getDeliveryDeadline()));
        service.expireInvocations(invocation.getDeliveryDeadline().minusSeconds(1));

        assertEquals("Pending", service.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2").getStatus());
        service.expireInvocations(invocation.getDeliveryDeadline());

        CommandInvocation timedOut = service.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2");
        assertEquals("TimedOut", timedOut.getStatus());
        assertEquals("Delivery Timed Out", timedOut.getStatusDetails());
        Command updated = service.listCommands(command.getCommandId(), null, "us-west-2").getFirst();
        assertEquals("Delivery Timed Out", updated.getStatusDetails());
        assertEquals(1, updated.getDeliveryTimedOutCount());
        assertEquals(0, updated.getErrorCount());
    }

    @Test
    void restartExpiresPendingDelivery() throws Exception {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmDirectCommandExecutor executor = mock(SsmDirectCommandExecutor.class);
        SsmCommandService first = service(storage, executor);
        Command command = first.sendCommand(request("i-agent", 30, "90"), "us-west-2");
        CommandInvocation invocation = first.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2");
        invocation.setDeliveryDeadline(Instant.now().minusSeconds(1));
        storage.invocations.put("us-west-2::" + command.getCommandId() + "::i-agent", invocation);

        SsmCommandService restarted = service(storage, executor);
        restarted.restorePersistedLifecycle();

        CommandInvocation timedOut = restarted.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2");
        assertEquals("TimedOut", timedOut.getStatus());
        assertEquals("Delivery Timed Out", timedOut.getStatusDetails());
    }

    @Test
    void acknowledgedInvocationUsesExecutionDeadlineAndLateReplyCannotOverwriteTimeout() throws Exception {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmCommandService service = service(storage, mock(SsmDirectCommandExecutor.class));
        Command command = service.sendCommand(request("i-agent", 30, "1"), "us-west-2");
        String messageId = (String) service.getMessages("i-agent", "request", 30).getFirst().get("MessageId");
        service.acknowledgeMessage(messageId);

        CommandInvocation running = service.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2");
        assertEquals("InProgress", running.getStatus());
        assertNotNull(running.getExecutionDeadline());
        service.expireInvocations(running.getExecutionDeadline());
        service.sendReply(messageId, java.util.Base64.getEncoder().encodeToString("{}".getBytes()));

        CommandInvocation timedOut = service.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2");
        assertEquals("TimedOut", timedOut.getStatus());
        assertEquals("Execution Timed Out", timedOut.getStatusDetails());
        assertEquals(0, service.listCommands(command.getCommandId(), null, "us-west-2")
                .getFirst().getDeliveryTimedOutCount());
    }

    @Test
    void restartReconcilesFinishedDirectExecution() throws Exception {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmDirectCommandExecutor executor = mock(SsmDirectCommandExecutor.class);
        SsmCommandService first = service(storage, executor);
        Command command = first.sendCommand(request("i-container", 60, "30"), "us-west-2");
        CommandInvocation persisted = first.getCommandInvocation(
                command.getCommandId(), "i-container", "us-west-2");
        Instant start = Instant.now();
        persisted.setStatus("InProgress");
        persisted.setDirectExecution(true);
        persisted.setDirectContainerId("container");
        persisted.setDirectExecId("exec");
        persisted.setDirectRuntimeFile("/tmp/run");
        persisted.setExecutionStartDateTime(start);
        persisted.setExecutionDeadline(start.plusSeconds(30));
        storage.invocations.put("us-west-2::" + command.getCommandId() + "::i-container", persisted);

        when(executor.inspectExecution(any())).thenReturn(SsmDirectCommandExecutor.ExecutionState.FINISHED);
        when(executor.recoverFinishedExecution(any())).thenReturn(Optional.of(
                SsmDirectCommandExecutor.ExecutionResult.success("", "", 0, Instant.now())));
        SsmCommandService restarted = service(storage, executor);
        restarted.restorePersistedLifecycle();

        assertEquals("Success", restarted.getCommandInvocation(
                command.getCommandId(), "i-container", "us-west-2").getStatus());
    }

    @Test
    void restartStopsOverdueDirectExecutionBeforeMarkingTimedOut() throws Exception {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmDirectCommandExecutor executor = mock(SsmDirectCommandExecutor.class);
        SsmCommandService service = service(storage, executor);
        Command command = service.sendCommand(request("i-agent", 30, "1"), "us-west-2");
        CommandInvocation invocation = service.getCommandInvocation(command.getCommandId(), "i-agent", "us-west-2");
        invocation.setStatus("InProgress");
        invocation.setDirectExecution(true);
        invocation.setDirectContainerId("container");
        invocation.setDirectExecId("exec");
        invocation.setDirectRuntimeFile("/tmp/run");
        invocation.setExecutionStartDateTime(Instant.now().minusSeconds(10));
        invocation.setExecutionDeadline(Instant.now().minusSeconds(1));
        storage.invocations.put("us-west-2::" + command.getCommandId() + "::i-agent", invocation);
        when(executor.inspectExecution(any())).thenReturn(SsmDirectCommandExecutor.ExecutionState.RUNNING);
        when(executor.stopExecution(any())).thenReturn(true);

        service.restorePersistedLifecycle();

        verify(executor).stopExecution(any());
        assertEquals("Execution Timed Out", service.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2").getStatusDetails());
    }

    @Test
    void restartRetainsActiveDirectExecutionAndFailsClosedWhenStopCannotBeVerified() throws Exception {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmDirectCommandExecutor executor = mock(SsmDirectCommandExecutor.class);
        SsmCommandService service = service(storage, executor);
        Command command = service.sendCommand(request("i-agent", 30, "1"), "us-west-2");
        CommandInvocation invocation = service.getCommandInvocation(command.getCommandId(), "i-agent", "us-west-2");
        invocation.setStatus("InProgress");
        invocation.setDirectExecution(true);
        invocation.setDirectContainerId("container");
        invocation.setDirectExecId("exec");
        invocation.setDirectRuntimeFile("/tmp/run");
        invocation.setExecutionStartDateTime(Instant.now());
        invocation.setExecutionDeadline(Instant.now().plusSeconds(30));
        storage.invocations.put("us-west-2::" + command.getCommandId() + "::i-agent", invocation);
        when(executor.inspectExecution(any())).thenReturn(SsmDirectCommandExecutor.ExecutionState.RUNNING);

        service.restorePersistedLifecycle();

        assertEquals("InProgress", service.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2").getStatus());

        invocation.setExecutionDeadline(Instant.now().minusSeconds(1));
        storage.invocations.put("us-west-2::" + command.getCommandId() + "::i-agent", invocation);
        when(executor.inspectExecution(any())).thenReturn(SsmDirectCommandExecutor.ExecutionState.UNKNOWN);
        when(executor.stopExecution(any())).thenReturn(false);

        service.restorePersistedLifecycle();

        assertEquals("InProgress", service.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2").getStatus());
    }

    @Test
    void lifecycleExpiresPendingDeliveriesAcrossAccounts() {
        AccountStorageFactory storage = new AccountStorageFactory();
        SsmCommandService service = new SsmCommandService(
                storage, objectMapper, regionResolver, mock(SsmDirectCommandExecutor.class));
        for (String accountId : List.of("111111111111", "222222222222")) {
            Command command = new Command();
            command.setCommandId("command");
            command.setRegion("us-west-2");
            command.setStatus("InProgress");
            command.setInstanceIds(List.of("i-agent"));
            CommandInvocation invocation = new CommandInvocation();
            invocation.setCommandId("command");
            invocation.setInstanceId("i-agent");
            invocation.setRegion("us-west-2");
            invocation.setStatus("Pending");
            invocation.setDeliveryDeadline(Instant.now().minusSeconds(1));
            storage.commands.putForAccount(accountId, "us-west-2::command", command);
            storage.invocations.putForAccount(
                    accountId, "us-west-2::command::i-agent", invocation);
        }

        service.restorePersistedLifecycle();

        for (String accountId : List.of("111111111111", "222222222222")) {
            assertEquals("TimedOut", storage.invocations.getForAccount(
                    accountId, "us-west-2::command::i-agent").orElseThrow().getStatus());
            assertEquals(1, storage.commands.getForAccount(
                    accountId, "us-west-2::command").orElseThrow().getDeliveryTimedOutCount());
            assertEquals(accountId, storage.commands.getForAccount(
                    accountId, "us-west-2::command").orElseThrow().getAccountId());
            assertEquals(accountId, storage.invocations.getForAccount(
                    accountId, "us-west-2::command::i-agent").orElseThrow().getAccountId());
        }
    }

    @Test
    void legacyNullAccountRecordsReconcileInTheirOwningAccount() {
        AccountStorageFactory storage = new AccountStorageFactory();
        SsmDirectCommandExecutor executor = mock(SsmDirectCommandExecutor.class);
        SsmCommandService service = new SsmCommandService(storage, objectMapper, regionResolver, executor);
        String accountId = "222222222222";
        Command command = command(null, "InProgress");
        CommandInvocation invocation = invocation(null, "TimedOut", "Execution Timed Out");
        storage.commands.putForAccount(accountId, "us-west-2::command", command);
        storage.invocations.putForAccount(accountId, "us-west-2::command::i-agent", invocation);

        service.restorePersistedLifecycle();

        Command repaired = storage.commands.getForAccount(accountId, "us-west-2::command").orElseThrow();
        assertEquals(accountId, repaired.getAccountId());
        assertEquals("TimedOut", repaired.getStatus());
        assertEquals(1, repaired.getErrorCount());
        assertEquals(accountId, storage.invocations.getForAccount(
                accountId, "us-west-2::command::i-agent").orElseThrow().getAccountId());
        assertTrue(storage.commands.getForAccount(
                "000000000000", "us-west-2::command").isEmpty());
        assertTrue(storage.invocations.getForAccount(
                "000000000000", "us-west-2::command::i-agent").isEmpty());
        verify(executor, never()).inspectExecution(any());
    }

    @Test
    void restartRepairsTerminalInvocationAndStaleParentAggregate() throws Exception {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmCommandService first = service(storage, mock(SsmDirectCommandExecutor.class));
        Command command = first.sendCommand(request("i-agent", 30, "1"), "us-west-2");
        CommandInvocation invocation = first.getCommandInvocation(
                command.getCommandId(), "i-agent", "us-west-2");
        invocation.setStatus("Failed");
        invocation.setStatusDetails("Failed");
        storage.invocations.put("us-west-2::" + command.getCommandId() + "::i-agent", invocation);

        SsmCommandService restarted = service(storage, mock(SsmDirectCommandExecutor.class));
        restarted.restorePersistedLifecycle();

        Command repaired = restarted.listCommands(command.getCommandId(), null, "us-west-2").getFirst();
        assertEquals("Failed", repaired.getStatus());
        assertEquals(1, repaired.getCompletedCount());
        assertEquals(1, repaired.getErrorCount());
    }

    @Test
    void commandCountersSeparateFailureExecutionTimeoutDeliveryTimeoutAndCancellation() {
        SharedStorageFactory storage = new SharedStorageFactory();
        SsmCommandService service = service(storage, mock(SsmDirectCommandExecutor.class));
        Command command = command(null, "InProgress");
        command.setInstanceIds(List.of("i-failed", "i-execution", "i-delivery", "i-cancelled"));
        command.setTargetCount(4);
        storage.commands.put("us-west-2::command", command);
        storage.invocations.put("us-west-2::command::i-failed",
                invocationFor("i-failed", "Failed", "Failed"));
        storage.invocations.put("us-west-2::command::i-execution",
                invocationFor("i-execution", "TimedOut", "Execution Timed Out"));
        storage.invocations.put("us-west-2::command::i-delivery",
                invocationFor("i-delivery", "TimedOut", "Delivery Timed Out"));
        storage.invocations.put("us-west-2::command::i-cancelled",
                invocationFor("i-cancelled", "Cancelled", "Cancelled"));

        service.restorePersistedLifecycle();

        Command counted = service.listCommands("command", null, "us-west-2").getFirst();
        assertEquals(4, counted.getCompletedCount());
        assertEquals(2, counted.getErrorCount());
        assertEquals(1, counted.getDeliveryTimedOutCount());
    }

    private static Command command(String accountId, String status) {
        Command command = new Command();
        command.setAccountId(accountId);
        command.setCommandId("command");
        command.setRegion("us-west-2");
        command.setStatus(status);
        command.setStatusDetails(status);
        command.setInstanceIds(List.of("i-agent"));
        command.setTargetCount(1);
        return command;
    }

    private static CommandInvocation invocation(String accountId, String status, String details) {
        CommandInvocation invocation = invocationFor("i-agent", status, details);
        invocation.setAccountId(accountId);
        return invocation;
    }

    private static CommandInvocation invocationFor(String instanceId, String status, String details) {
        CommandInvocation invocation = new CommandInvocation();
        invocation.setCommandId("command");
        invocation.setInstanceId(instanceId);
        invocation.setRegion("us-west-2");
        invocation.setStatus(status);
        invocation.setStatusDetails(details);
        return invocation;
    }

    private com.fasterxml.jackson.databind.JsonNode request(String instanceId, int delivery, String execution)
            throws Exception {
        return objectMapper.readTree("""
                {"InstanceIds":["%s"],"DocumentName":"AWS-RunShellScript",
                 "Parameters":{"commands":["echo ok"],"executionTimeout":["%s"]},
                 "TimeoutSeconds":%d}
                """.formatted(instanceId, execution, delivery));
    }

    private SsmCommandService service(SharedStorageFactory storage, SsmDirectCommandExecutor executor) {
        return new SsmCommandService(storage, objectMapper, regionResolver, executor);
    }

    private static final class SharedStorageFactory extends StorageFactory {
        private final StorageBackend<String, Object> instances = new InMemoryStorage<>();
        private final StorageBackend<String, Object> commands = new InMemoryStorage<>();
        private final StorageBackend<String, Object> invocations = new InMemoryStorage<>();

        private SharedStorageFactory() { super(null, null); }

        @Override
        @SuppressWarnings("unchecked")
        public <V> StorageBackend<String, V> create(String serviceName, String fileName,
                                                    TypeReference<Map<String, V>> typeReference) {
            return (StorageBackend<String, V>) switch (fileName) {
                case "ssm-instances.json" -> instances;
                case "ssm-commands.json" -> commands;
                case "ssm-invocations.json" -> invocations;
                default -> throw new IllegalArgumentException(fileName);
            };
        }
    }

    private static final class AccountStorageFactory extends StorageFactory {
        private final AccountAwareStorageBackend<Command> commands = new AccountAwareStorageBackend<>(
                new InMemoryStorage<>(), null, "000000000000");
        private final AccountAwareStorageBackend<CommandInvocation> invocations = new AccountAwareStorageBackend<>(
                new InMemoryStorage<>(), null, "000000000000");

        private AccountStorageFactory() { super(null, null); }

        @Override
        @SuppressWarnings("unchecked")
        public <V> StorageBackend<String, V> create(String serviceName, String fileName,
                                                    TypeReference<Map<String, V>> typeReference) {
            return switch (fileName) {
                case "ssm-instances.json" -> new InMemoryStorage<>();
                case "ssm-commands.json" -> (StorageBackend<String, V>) commands;
                case "ssm-invocations.json" -> (StorageBackend<String, V>) invocations;
                default -> throw new IllegalArgumentException(fileName);
            };
        }
    }
}
