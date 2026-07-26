package io.github.hectorvent.floci.services.ssm;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.StreamType;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.model.GuestCommandReadiness;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

@ApplicationScoped
public class SsmDirectCommandExecutor {

    private static final Logger LOG = Logger.getLogger(SsmDirectCommandExecutor.class);
    static final int DEFAULT_EXECUTION_TIMEOUT_SECONDS = 3_600;
    static final int MAX_EXECUTION_TIMEOUT_SECONDS = 172_800;

    private final DockerClient dockerClient;
    private final Ec2Service ec2Service;

    @Inject
    public SsmDirectCommandExecutor(DockerClient dockerClient, Ec2Service ec2Service) {
        this.dockerClient = dockerClient;
        this.ec2Service = ec2Service;
    }

    public Optional<ExecutionResult> executeIfSupported(
            String instanceId,
            String documentName,
            Map<String, List<String>> parameters,
            int executionTimeoutSeconds) {
        return executeIfSupported(instanceId, documentName, parameters, executionTimeoutSeconds, ignored -> {});
    }

    public Optional<ExecutionResult> executeIfSupported(
            String instanceId,
            String documentName,
            Map<String, List<String>> parameters,
            int executionTimeoutSeconds,
            Consumer<ExecutionIdentity> identityConsumer) {
        if (!supports(instanceId, documentName)) {
            return Optional.empty();
        }

        Instance instance = ec2Service.findInstanceById(instanceId);
        if (instance == null) {
            return Optional.of(ExecutionResult.failed(
                    "", "EC2 guest command execution became unavailable", 1));
        }
        String script = String.join("\n", parameters.getOrDefault("commands", List.of()));

        String workingDirectory = parameters.getOrDefault("workingDirectory", List.of(""))
                .stream()
                .filter(value -> value != null && !value.isBlank())
                .findFirst()
                .orElse(null);

        try {
            GuestCommandReadiness readiness = awaitGuestCommandReadiness(instance, executionTimeoutSeconds);
            if (readiness == GuestCommandReadiness.UNAVAILABLE) {
                return Optional.of(ExecutionResult.failed(
                        "", "EC2 guest command execution became unavailable", 1));
            }
            if (readiness != GuestCommandReadiness.READY) {
                return Optional.of(ExecutionResult.timedOut(
                        "", "EC2 guest command execution was not ready before the command timeout", Instant.now()));
            }
            if (script.isBlank()) {
                return Optional.of(ExecutionResult.success("", "", 0));
            }
            return Optional.of(executeInContainer(
                    instance.getDockerContainerId(), script, workingDirectory, executionTimeoutSeconds, identityConsumer));
        }
        catch (Exception e) {
            LOG.warnv(e, "SSM direct command failed for instance {0}", instanceId);
            return Optional.of(ExecutionResult.failed("", e.getMessage() != null ? e.getMessage() : e.toString(), 1));
        }
    }

    public boolean supports(String instanceId, String documentName) {
        if (!"AWS-RunShellScript".equals(documentName)) {
            return false;
        }

        Instance instance = ec2Service.findInstanceById(instanceId);
        if (instance == null || instance.getDockerContainerId() == null || instance.getDockerContainerId().isBlank()) {
            return false;
        }
        return ec2Service.isInstanceContainerRunning(instanceId);
    }

    private static GuestCommandReadiness awaitGuestCommandReadiness(
            Instance instance,
            int timeoutSeconds)
            throws InterruptedException {
        long remainingNanos = TimeUnit.SECONDS.toNanos(Math.max(0, timeoutSeconds));
        long deadline = System.nanoTime() + remainingNanos;
        synchronized (instance) {
            while (instance.getGuestCommandReadiness() == GuestCommandReadiness.PENDING
                    && remainingNanos > 0) {
                TimeUnit.NANOSECONDS.timedWait(instance, remainingNanos);
                remainingNanos = deadline - System.nanoTime();
            }
            GuestCommandReadiness readiness = instance.getGuestCommandReadiness();
            return readiness != null ? readiness : GuestCommandReadiness.READY;
        }
    }

    private ExecutionResult executeInContainer(
            String containerId,
            String script,
            String workingDirectory,
            int executionTimeoutSeconds,
            Consumer<ExecutionIdentity> identityConsumer)
            throws InterruptedException {
        String runtimeFile = "/tmp/floci-ssm-" + java.util.UUID.randomUUID();
        String[] cmd = {"sh", "-c", timeoutWrappedScript(script, executionTimeoutSeconds, runtimeFile)};
        var create = dockerClient.execCreateCmd(containerId)
                .withCmd(cmd)
                .withAttachStdout(true)
                .withAttachStderr(true);
        if (workingDirectory != null) {
            create.withWorkingDir(workingDirectory);
        }

        String execId = create.exec().getId();
        Instant start = Instant.now();
        identityConsumer.accept(new ExecutionIdentity(
                containerId, execId, runtimeFile, start, start.plusSeconds(executionTimeoutSeconds)));
        CountDownLatch latch = new CountDownLatch(1);
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();

        ResultCallback<Frame> callback = dockerClient.execStartCmd(execId).exec(new ResultCallback.Adapter<Frame>() {
            @Override
            public void onNext(Frame frame) {
                byte[] payload = frame.getPayload();
                if (payload == null) {
                    return;
                }
                ByteArrayOutputStream target = frame.getStreamType() == StreamType.STDERR ? stderr : stdout;
                try {
                    target.write(payload);
                }
                catch (IOException e) {
                    LOG.debug("Unable to capture SSM direct command output", e);
                }
            }

            @Override
            public void onComplete() {
                latch.countDown();
            }

            @Override
            public void onError(Throwable throwable) {
                try {
                    stderr.write((throwable.getMessage() != null ? throwable.getMessage() : throwable.toString())
                            .getBytes(StandardCharsets.UTF_8));
                }
                catch (IOException e) {
                    LOG.debug("Unable to capture SSM direct command failure", e);
                }
                latch.countDown();
            }
        });

        boolean completed = latch.await(hostTimeoutSeconds(executionTimeoutSeconds), TimeUnit.SECONDS);
        if (!completed) {
            closeQuietly(callback);
            if (!stopExecution(containerId, execId, runtimeFile)) {
                return ExecutionResult.inProgress(start);
            }
            return ExecutionResult.timedOut(
                    stdout.toString(StandardCharsets.UTF_8),
                    "Timed out after " + executionTimeoutSeconds + "s",
                    start);
        }

        Long exitCode = dockerClient.inspectExecCmd(execId).exec().getExitCodeLong();
        int responseCode = exitCode != null ? exitCode.intValue() : 1;
        String standardOutput = stdout.toString(StandardCharsets.UTF_8);
        String standardError = stderr.toString(StandardCharsets.UTF_8);
        if (isTimeoutExitCode(responseCode)) {
            logFailureDiagnostics(containerId);
            return ExecutionResult.timedOut(standardOutput, standardError, start);
        }
        if (responseCode == 0) {
            return ExecutionResult.success(standardOutput, standardError, responseCode, start);
        }
        logFailureDiagnostics(containerId);
        return ExecutionResult.failed(standardOutput, standardError, responseCode, start);
    }

    static String timeoutWrappedScript(String script, int timeoutSeconds) {
        return timeoutWrappedScript(script, timeoutSeconds, "/tmp/floci-ssm-runtime");
    }

    static String timeoutWrappedScript(String script, int timeoutSeconds, String runtimeFile) {
        String command = "sh -c " + shellSingleQuote(script);
        if (timeoutSeconds < 1) {
            return command;
        }
        String timeout = timeoutSeconds + "s";
        String timed = "if command -v timeout >/dev/null 2>&1; then exec timeout --kill-after=1s "
                + shellSingleQuote(timeout) + " " + command + "; else exec " + command + "; fi";
        return "runtime_file=" + shellSingleQuote(runtimeFile) + "; "
                + "if command -v setsid >/dev/null 2>&1; then setsid sh -c " + shellSingleQuote(timed)
                + " & else sh -c " + shellSingleQuote(timed) + " & fi; "
                + "pid=$!; echo \"$pid\" > \"$runtime_file\"; "
                + "wait \"$pid\"; rc=$?; rm -f \"$runtime_file\"; exit \"$rc\"";
    }

    public ExecutionState inspectExecution(ExecutionIdentity identity) {
        try {
            var inspection = dockerClient.inspectExecCmd(identity.execId()).exec();
            if (Boolean.TRUE.equals(inspection.isRunning())) {
                return ExecutionState.RUNNING;
            }
            return inspection.getExitCodeLong() == null ? ExecutionState.UNKNOWN : ExecutionState.FINISHED;
        }
        catch (Exception e) {
            LOG.debugv(e, "Unable to inspect SSM Docker exec {0}", identity.execId());
            return ExecutionState.UNKNOWN;
        }
    }

    public boolean stopExecution(ExecutionIdentity identity) {
        return stopExecution(identity.containerId(), identity.execId(), identity.runtimeFile());
    }

    public Optional<ExecutionResult> recoverFinishedExecution(ExecutionIdentity identity) {
        try {
            var inspection = dockerClient.inspectExecCmd(identity.execId()).exec();
            if (Boolean.TRUE.equals(inspection.isRunning()) || inspection.getExitCodeLong() == null) {
                return Optional.empty();
            }
            int responseCode = inspection.getExitCodeLong().intValue();
            Instant start = identity.startedAt() != null ? identity.startedAt() : Instant.now();
            if (isTimeoutExitCode(responseCode)) {
                return Optional.of(ExecutionResult.timedOut("", "", start));
            }
            if (responseCode == 0) {
                return Optional.of(ExecutionResult.success("", "", 0, start));
            }
            return Optional.of(ExecutionResult.failed("", "", responseCode, start));
        }
        catch (Exception e) {
            LOG.debugv(e, "Unable to recover SSM Docker exec {0}", identity.execId());
            return Optional.empty();
        }
    }

    private boolean stopExecution(String containerId, String execId, String runtimeFile) {
        try {
            String script = "runtime_file=" + shellSingleQuote(runtimeFile) + "; "
                    + "pid=$(cat \"$runtime_file\" 2>/dev/null || true); "
                    + "if [ -n \"$pid\" ]; then kill -TERM -- -\"$pid\" 2>/dev/null || kill -TERM \"$pid\" 2>/dev/null || true; fi; "
                    + "sleep 1; "
                    + "if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; then "
                    + "kill -KILL -- -\"$pid\" 2>/dev/null || kill -KILL \"$pid\" 2>/dev/null || true; fi; "
                    + "rm -f \"$runtime_file\"";
            var stop = dockerClient.execCreateCmd(containerId)
                    .withCmd("sh", "-c", script)
                    .withAttachStdout(false)
                    .withAttachStderr(false)
                    .exec();
            CountDownLatch latch = new CountDownLatch(1);
            ResultCallback<Frame> callback = dockerClient.execStartCmd(stop.getId()).exec(new ResultCallback.Adapter<Frame>() {
                @Override
                public void onComplete() { latch.countDown(); }

                @Override
                public void onError(Throwable throwable) { latch.countDown(); }
            });
            boolean completed = latch.await(3, TimeUnit.SECONDS);
            if (!completed) {
                closeQuietly(callback);
                return false;
            }
            return inspectExecution(new ExecutionIdentity(
                    containerId, execId, runtimeFile, null, null)) == ExecutionState.FINISHED;
        }
        catch (Exception e) {
            LOG.warnv(e, "Unable to stop SSM Docker exec {0}", execId);
            return false;
        }
    }

    static int executionTimeoutSeconds(Map<String, List<String>> parameters) {
        List<String> values = parameters.get("executionTimeout");
        if (values == null) {
            return DEFAULT_EXECUTION_TIMEOUT_SECONDS;
        }
        if (values.size() != 1) {
            throw new IllegalArgumentException("executionTimeout must contain exactly one value");
        }
        String value = values.getFirst();
        if (value == null || !value.matches("[1-9][0-9]{0,6}")) {
            throw new IllegalArgumentException("executionTimeout must be an integer from 1 to 172800");
        }
        try {
            int parsed = Integer.parseInt(value);
            if (parsed > MAX_EXECUTION_TIMEOUT_SECONDS) {
                throw new IllegalArgumentException("executionTimeout must be an integer from 1 to 172800");
            }
            return parsed;
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("executionTimeout must be an integer from 1 to 172800", e);
        }
    }

    static String diagnosticWrappedScript(String script) {
        return "sh -c " + shellSingleQuote(script);
    }

    private void logFailureDiagnostics(String containerId) {
        try {
            String diagnostics = collectFailureDiagnostics(containerId);
            if (!diagnostics.isBlank()) {
                LOG.warnf("SSM direct command failed; compact service diagnostics:%n%s", diagnostics);
            }
        }
        catch (Exception e) {
            LOG.debugv(e, "Unable to collect SSM direct command diagnostics for container {0}", containerId);
        }
    }

    private String collectFailureDiagnostics(String containerId) throws InterruptedException {
        var create = dockerClient.execCreateCmd(containerId)
                .withCmd("sh", "-c", failureDiagnosticsScript())
                .withAttachStdout(true)
                .withAttachStderr(true);
        String execId = create.exec().getId();
        CountDownLatch latch = new CountDownLatch(1);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ResultCallback<Frame> callback = dockerClient.execStartCmd(execId).exec(new ResultCallback.Adapter<Frame>() {
            @Override
            public void onNext(Frame frame) {
                byte[] payload = frame.getPayload();
                if (payload == null) {
                    return;
                }
                try {
                    output.write(payload);
                }
                catch (IOException e) {
                    LOG.debug("Unable to capture SSM direct command diagnostics", e);
                }
            }

            @Override
            public void onComplete() {
                latch.countDown();
            }

            @Override
            public void onError(Throwable throwable) {
                latch.countDown();
            }
        });
        boolean completed = latch.await(2, TimeUnit.SECONDS);
        if (!completed) {
            closeQuietly(callback);
        }
        return output.toString(StandardCharsets.UTF_8);
    }

    static String failureDiagnosticsScript() {
        return """
                floci_ssm_redact() {
                  sed -E \\
                    -e 's/(Authorization:[[:space:]]*Bearer[[:space:]]*)[^[:space:]]+/\\1[REDACTED]/Ig' \\
                    -e 's/((password|passwd|secret|token|client[-_ ]?secret)[^=:\\r\\n]{0,80}[=:][[:space:]]*)[^[:space:]]+/\\1[REDACTED]/Ig'
                }
                echo "[floci:ssm] listening ports"
                (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true) | head -40 | floci_ssm_redact
                echo "[floci:ssm] processes"
                (ps -eo pid,ppid,comm,args 2>/dev/null || ps aux 2>/dev/null || true) | head -40 | floci_ssm_redact || true
                log_count=0
                for log in /var/log/*.log /var/log/*/*.log; do
                  [ -f "$log" ] || continue
                  log_count=$((log_count + 1))
                  [ "$log_count" -le 5 ] || break
                  echo "[floci:ssm] log tail: $log"
                  tail -40 "$log" 2>/dev/null | floci_ssm_redact || true
                done
                """;
    }

    private static long hostTimeoutSeconds(int timeoutSeconds) {
        if (timeoutSeconds < 1) {
            return 0;
        }
        return timeoutSeconds + 2L;
    }

    private static boolean isTimeoutExitCode(int responseCode) {
        return responseCode == 124 || responseCode == 137 || responseCode == 143;
    }

    private static String shellSingleQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        }
        catch (IOException e) {
            LOG.debug("Unable to close SSM Docker exec callback", e);
        }
    }

    public record ExecutionResult(
            String status,
            String standardOutput,
            String standardError,
            int responseCode,
            Instant executionStartDateTime,
            Instant executionEndDateTime) {
        static ExecutionResult success(String standardOutput, String standardError, int responseCode) {
            return success(standardOutput, standardError, responseCode, Instant.now());
        }

        static ExecutionResult success(String standardOutput, String standardError, int responseCode, Instant start) {
            return new ExecutionResult("Success", standardOutput, standardError, responseCode, start, Instant.now());
        }

        static ExecutionResult failed(String standardOutput, String standardError, int responseCode) {
            return failed(standardOutput, standardError, responseCode, Instant.now());
        }

        static ExecutionResult failed(String standardOutput, String standardError, int responseCode, Instant start) {
            return new ExecutionResult("Failed", standardOutput, standardError, responseCode, start, Instant.now());
        }

        static ExecutionResult timedOut(String standardOutput, String standardError, Instant start) {
            return new ExecutionResult("TimedOut", standardOutput, standardError, -1, start, Instant.now());
        }

        static ExecutionResult inProgress(Instant start) {
            return new ExecutionResult("InProgress", "", "", -1, start, null);
        }
    }

    public record ExecutionIdentity(
            String containerId,
            String execId,
            String runtimeFile,
            Instant startedAt,
            Instant deadline) {}

    public enum ExecutionState {
        RUNNING,
        FINISHED,
        UNKNOWN
    }
}
