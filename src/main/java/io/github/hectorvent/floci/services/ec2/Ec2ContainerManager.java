package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLogStreamer;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import io.github.hectorvent.floci.core.common.docker.ContainerStorageHelper;
import io.github.hectorvent.floci.core.common.docker.DockerHostResolver;
import io.github.hectorvent.floci.core.common.docker.PortAllocator;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.InstanceState;
import io.github.hectorvent.floci.services.ec2.portforward.Ec2PortForwardManager;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.Mount;
import com.github.dockerjava.api.model.MountType;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manages Docker container lifecycle for EC2 instances.
 * Handles launch, stop, start, terminate, and reboot operations.
 * SSH key injection and UserData execution are performed asynchronously after launch.
 */
@ApplicationScoped
public class Ec2ContainerManager {

    private static final Logger LOG = Logger.getLogger(Ec2ContainerManager.class);
    private static final String USER_DATA_SCRIPT_PATH = "/tmp/user-data.sh";
    private static final String PRE_SYSTEMD_ENTRYPOINT = "/usr/local/sbin/floci-ec2-pre-systemd";
    private static final String SYSTEMD_RELEASE_PATH = "/run/floci-ec2/start-systemd";
    private static final Pattern MIME_BOUNDARY = Pattern.compile("(?im)^content-type:\\s*multipart/[^;]+;\\s*boundary=\"?([^\";\\n\\r]+)\"?.*$");
    static int containerBridgeIpAttempts = 30;
    static long containerBridgeIpPollMillis = 500;
    static int metadataProxyInstallTimeoutSeconds = 180;

    private final ContainerBuilder containerBuilder;
    private final ContainerLifecycleManager lifecycleManager;
    private final ContainerLogStreamer logStreamer;
    private final ContainerDetector containerDetector;
    private final DockerHostResolver dockerHostResolver;
    private final DockerClient dockerClient;
    private final PortAllocator portAllocator;
    private final EmulatorConfig config;
    private final Ec2MetadataServer metadataServer;
    private final Ec2PortForwardManager portForwardManager;

    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "ec2-container-launcher");
        t.setDaemon(true);
        return t;
    });

    @Inject
    public Ec2ContainerManager(ContainerBuilder containerBuilder,
                               ContainerLifecycleManager lifecycleManager,
                               ContainerLogStreamer logStreamer,
                               ContainerDetector containerDetector,
                               DockerHostResolver dockerHostResolver,
                               DockerClient dockerClient,
                               PortAllocator portAllocator,
                               EmulatorConfig config,
                               Ec2MetadataServer metadataServer,
                               Ec2PortForwardManager portForwardManager) {
        this.containerBuilder = containerBuilder;
        this.lifecycleManager = lifecycleManager;
        this.logStreamer = logStreamer;
        this.containerDetector = containerDetector;
        this.dockerHostResolver = dockerHostResolver;
        this.dockerClient = dockerClient;
        this.portAllocator = portAllocator;
        this.config = config;
        this.metadataServer = metadataServer;
        this.portForwardManager = portForwardManager;
    }

    /**
     * Launches a Docker container for the given EC2 instance.
     * The instance starts in pending state; an async thread transitions it to running
     * and handles SSH key injection and UserData execution.
     *
     * @param instance    the EC2 instance model (mutated in-place as state transitions occur)
     * @param dockerImage Docker image URI resolved from the instance's AMI ID
     * @param publicKey   SSH public key content to inject (may be null)
     * @param region      AWS region (for CloudWatch log group naming)
     */
    public void launch(Instance instance, String dockerImage, String publicKey, String region) {
        launch(instance, ResolvedAmiImage.minimal(dockerImage), publicKey, region, Set.of());
    }

    public void launch(Instance instance, ResolvedAmiImage image, String publicKey, String region) {
        launch(instance, image, publicKey, region, Set.of());
    }

    /**
     * @param appPorts TCP ports opened by the instance's security groups to publish on the host
     *                 via socat sidecars once the container is running (empty for none)
     */
    public void launch(Instance instance, ResolvedAmiImage image, String publicKey, String region, Set<Integer> appPorts) {
        instance.setState(InstanceState.pending());

        executor.submit(() -> {
            try {
                String instanceId = instance.getInstanceId();
                String containerName = ContainerStorageHelper.resourceName(config, "ec2", null, instanceId);

                // Allocate SSH host port
                int sshHostPort = portAllocator.allocate(
                        config.services().ec2().sshPortRangeStart(),
                        config.services().ec2().sshPortRangeEnd());
                instance.setSshHostPort(sshHostPort);

                // IMDS endpoint that this container should use
                String flociHost = dockerHostResolver.resolve();
                int imdsPort = config.services().ec2().imdsPort();
                String imdsEndpoint = "http://" + flociHost + ":" + imdsPort;
                String serviceEndpoint = "http://" + flociHost + ":4566";

                // Build container spec — minimal images keep the historic tail
                // command, while cloud-image AMI guests can boot their init.
                ContainerBuilder.Builder specBuilder = containerBuilder.newContainer(image.dockerImage())
                        .withName(containerName)
                        .withEmbeddedDns()
                        .withDockerNetwork(Optional.empty())
                        .withEnv(localAwsEnvironment(instance, region, serviceEndpoint, imdsEndpoint))
                        .withEnv("AWS_EC2_INSTANCE_ID", instanceId)
                        .withPortBinding(22, sshHostPort)
                        .withHostDockerInternalOnLinux()
                        .withLogRotation()
                        // EC2 instances expose IMDS on 169.254.169.254. Floci
                        // needs network administration privileges in the local
                        // container to attach that link-local address.
                        .withPrivileged(true)
                        .withCmd(image.systemd() ? List.of("/sbin/init") : List.of("tail", "-f", "/dev/null"));
                if (image.systemd() && image.cloudInit()) {
                    specBuilder.withEntrypoint(List.of(PRE_SYSTEMD_ENTRYPOINT));
                }
                if (image.systemd()) {
                    specBuilder
                            .withCgroupnsMode("host")
                            .withMount(new Mount().withType(MountType.TMPFS).withTarget("/run"))
                            .withMount(new Mount().withType(MountType.TMPFS).withTarget("/run/lock"))
                            .withBind("/sys/fs/cgroup", "/sys/fs/cgroup");
                }
                ContainerSpec spec = specBuilder.build();

                // Create container without starting it
                String containerId = lifecycleManager.create(spec);
                instance.setDockerContainerId(containerId);

                if (image.systemd() && image.cloudInit()) {
                    try {
                        installPreSystemdEntrypoint(containerId);
                    }
                    catch (Exception e) {
                        LOG.warnv("Could not install pre-systemd entrypoint for EC2 instance {0}: {1}",
                                instanceId, e.getMessage());
                        cleanupFailedLaunch(instance, containerId, null, sshHostPort);
                        return;
                    }
                }

                // Start the container
                lifecycleManager.startCreated(containerId, spec);

                // Poll until Docker confirms the container is running
                boolean running = false;
                for (int i = 0; i < 30 && !running; i++) {
                    running = lifecycleManager.isContainerRunning(containerId);
                    if (!running) {
                        Thread.sleep(500);
                    }
                }

                if (!running) {
                    LOG.warnv("EC2 instance {0} container {1} did not reach running state", instanceId, containerId);
                    instance.setState(InstanceState.terminated());
                    return;
                }

                // Discover the container's bridge IP for IMDS registration.
                // Docker can report the container as running before network
                // settings are populated; wait here so IMDS is registered
                // before link-local metadata validation and UserData run.
                ContainerNetworkAddress containerAddress = waitForContainerNetworkAddress(containerId, instanceId);
                String containerIp = containerAddress != null ? containerAddress.ipAddress() : null;
                if (containerIp != null && !containerIp.isBlank()) {
                    instance.setContainerBridgeIp(containerIp);
                    exposeReachableNetworkAddress(instance, containerAddress);
                    metadataServer.registerContainer(containerIp, instanceId, instance);
                }
                else {
                    LOG.warnv("EC2 instance {0} container {1} did not receive a usable bridge IP for IMDS",
                            instanceId, containerId);
                    cleanupFailedLaunch(instance, containerId, null, sshHostPort);
                    return;
                }

                // Populate every advertised metadata leaf before native cloud-init is released.
                instance.setPublicIpAddress("127.0.0.1");
                instance.setPublicDnsName("localhost");

                boolean metadataReady = image.systemd() && image.cloudInit()
                        ? configureNativeCloudInitMetadata(containerId, instanceId, flociHost, imdsPort)
                        : configureLinkLocalMetadataEndpoint(containerId, instanceId, flociHost, imdsPort);
                if (!metadataReady) {
                    cleanupFailedLaunch(instance, containerId, containerIp, sshHostPort);
                    return;
                }

                instance.setState(InstanceState.running());
                LOG.infov("EC2 instance {0} running in container {1} (SSH host port {2})",
                        instanceId, containerId, String.valueOf(sshHostPort));

                // Publish security-group TCP ingress ports on the host via socat sidecars.
                if (appPorts != null && !appPorts.isEmpty()) {
                    portForwardManager.reconcile(instance, appPorts);
                }

                // Inject SSH public key
                if (publicKey != null && !publicKey.isBlank()) {
                    injectSshKey(containerId, publicKey);
                    startSshd(containerId, instanceId);
                }

                // Execute UserData
                Ec2UserData userData = instance.getEncodedUserData() != null
                        ? Ec2UserData.fromEncoded(instance.getEncodedUserData())
                        : Ec2UserData.fromText(instance.getUserData());
                if (!image.cloudInit() && userData != null && userData.bytes().length > 0) {
                    executeUserData(containerId, instanceId, userDataExecutionText(userData), region);
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                instance.setState(InstanceState.terminated());
            } catch (Exception e) {
                LOG.warnv("Failed to launch EC2 instance {0}: {1}", instance.getInstanceId(), e.getMessage());
                instance.setState(InstanceState.terminated());
            }
        });
    }

    /**
     * Synchronous stop for emulator shutdown: tears down the port-forward sidecars and
     * stops the container with a short timeout so N instances cannot exhaust the SIGTERM
     * grace window. Unlike {@link #stop}, runs on the caller's thread (the async executor
     * would be abandoned mid-flight during shutdown) and leaves state handling to the caller.
     */
    public void stopForShutdown(Instance instance) {
        String containerId = instance.getDockerContainerId();
        if (containerId == null) {
            return;
        }
        portForwardManager.unpublishAll(instance);
        try {
            dockerClient.stopContainerCmd(containerId).withTimeout(5).exec();
        } catch (NotFoundException e) {
            // already gone
        } catch (Exception e) {
            LOG.warnv("Error stopping EC2 container {0} on shutdown: {1}", containerId, e.getMessage());
        }
    }

    /**
     * Gracefully stops a running container (30 second timeout then SIGKILL).
     * Updates instance state through stopping → stopped.
     */
    public void stop(Instance instance) {
        String containerId = instance.getDockerContainerId();
        if (containerId == null) {
            instance.setState(InstanceState.stopped());
            return;
        }
        instance.setState(InstanceState.stopping());
        executor.submit(() -> {
            // Sidecars forward to the container's current IP, which Docker reassigns on the
            // next start; tear them down so no forward is left pointing at a stale address.
            portForwardManager.unpublishAll(instance);
            try {
                if (instance.isNativeCloudInit()) {
                    execInContainerForResult(containerId,
                            new String[]{"rm", "-f", SYSTEMD_RELEASE_PATH}, 5);
                }
                dockerClient.stopContainerCmd(containerId).withTimeout(30).exec();
            } catch (NotFoundException e) {
                // already gone
            } catch (Exception e) {
                LOG.warnv("Error stopping EC2 container {0}: {1}", containerId, e.getMessage());
            }
            instance.setState(InstanceState.stopped());
        });
    }

    /**
     * Starts a previously stopped container.
     * Updates instance state through pending → running.
     */
    public void start(Instance instance) {
        String containerId = instance.getDockerContainerId();
        if (containerId == null) {
            instance.setState(InstanceState.running());
            return;
        }
        instance.setState(InstanceState.pending());
        executor.submit(() -> {
            try {
                dockerClient.startContainerCmd(containerId).exec();
                boolean running = false;
                for (int i = 0; i < 20 && !running; i++) {
                    running = lifecycleManager.isContainerRunning(containerId);
                    if (!running) {
                        Thread.sleep(500);
                    }
                }
                String instanceId = instance.getInstanceId();
                ContainerNetworkAddress containerAddress = waitForContainerNetworkAddress(containerId, instanceId);
                String containerIp = containerAddress != null ? containerAddress.ipAddress() : null;
                if (containerIp != null && !containerIp.isBlank()) {
                    instance.setContainerBridgeIp(containerIp);
                    exposeReachableNetworkAddress(instance, containerAddress);
                    metadataServer.registerContainer(containerIp, instanceId, instance);
                }
                else {
                    cleanupFailedLaunch(instance, containerId, instance.getContainerBridgeIp(), instance.getSshHostPort());
                    return;
                }
                String flociHost = dockerHostResolver.resolve();
                int imdsPort = config.services().ec2().imdsPort();
                boolean metadataReady = instance.isNativeCloudInit()
                        ? configureNativeCloudInitMetadata(containerId, instanceId, flociHost, imdsPort)
                        : configureLinkLocalMetadataEndpoint(containerId, instanceId, flociHost, imdsPort);
                if (!metadataReady) {
                    cleanupFailedLaunch(instance, containerId, containerIp, instance.getSshHostPort());
                    return;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                LOG.warnv("Error starting EC2 container {0}: {1}", containerId, e.getMessage());
            }
            instance.setState(InstanceState.running());
        });
    }

    boolean isContainerRunning(String containerId) {
        return containerId != null && !containerId.isBlank() && lifecycleManager.isContainerRunning(containerId);
    }

    boolean restoreMetadataRegistration(Instance instance) {
        if (instance == null || instance.getDockerContainerId() == null) {
            return false;
        }
        String containerId = instance.getDockerContainerId();
        if (!lifecycleManager.isContainerRunning(containerId)) {
            return false;
        }

        ContainerNetworkAddress containerAddress = getContainerNetworkAddress(containerId);
        String containerIp = containerAddress != null ? containerAddress.ipAddress() : null;
        if (containerIp == null || containerIp.isBlank()) {
            containerIp = instance.getContainerBridgeIp();
            containerAddress = new ContainerNetworkAddress(containerIp, null);
        }
        if (containerIp == null || containerIp.isBlank()) {
            LOG.warnv("Could not restore IMDS registration for EC2 instance {0}: no container IP",
                    instance.getInstanceId());
            return false;
        }

        String previousContainerIp = instance.getContainerBridgeIp();
        if (previousContainerIp != null && !previousContainerIp.isBlank() && !previousContainerIp.equals(containerIp)) {
            metadataServer.unregisterContainer(previousContainerIp, instance);
        }
        instance.setContainerBridgeIp(containerIp);
        exposeReachableNetworkAddress(instance, containerAddress);
        metadataServer.registerContainer(containerIp, instance.getInstanceId(), instance);
        return true;
    }

    static void exposeReachablePrivateAddress(Instance instance, String privateIp) {
        exposeReachableNetworkAddress(instance, new ContainerNetworkAddress(privateIp, null));
    }

    static void exposeReachableNetworkAddress(Instance instance, ContainerNetworkAddress address) {
        String privateIp = address != null ? address.ipAddress() : null;
        if (instance == null || privateIp == null || privateIp.isBlank()) {
            return;
        }

        String privateDnsName = "ip-" + privateIp.replace('.', '-') + ".ec2.internal";
        instance.setPrivateIpAddress(privateIp);
        instance.setPrivateDnsName(privateDnsName);
        if (instance.getNetworkInterfaces() != null) {
            instance.getNetworkInterfaces().forEach(networkInterface -> {
                networkInterface.setPrivateIpAddress(privateIp);
                networkInterface.setPrivateDnsName(privateDnsName);
                if (address.macAddress() != null && !address.macAddress().isBlank()) {
                    networkInterface.setMacAddress(address.macAddress());
                }
            });
        }
    }

    /**
     * Terminates an instance: forcefully removes the container.
     * Updates state through shutting-down → terminated.
     * Sets terminatedAt for TTL pruning.
     */
    public void terminate(Instance instance) {
        String containerId = instance.getDockerContainerId();
        String containerIp = instance.getContainerBridgeIp();
        int sshHostPort = instance.getSshHostPort();
        instance.setState(InstanceState.shuttingDown());
        executor.submit(() -> {
            portForwardManager.unpublishAll(instance);
            if (containerId != null) {
                try {
                    dockerClient.removeContainerCmd(containerId).withForce(true).exec();
                } catch (NotFoundException e) {
                    // already gone
                } catch (Exception e) {
                    LOG.warnv("Error removing EC2 container {0}: {1}", containerId, e.getMessage());
                }
                try {
                    // iptables/veth teardown lags behind container removal; prevents port-reuse conflicts.
                    Thread.sleep(500);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
            if (sshHostPort > 0) {
                portAllocator.release(sshHostPort);
            }
            metadataServer.unregisterContainer(containerIp, instance);
            metadataServer.unregisterInstance(instance);
            instance.setState(InstanceState.terminated());
            instance.setTerminatedAt(System.currentTimeMillis());
        });
    }

    /**
     * Reboots an instance via docker restart.
     */
    public void reboot(Instance instance) {
        String containerId = instance.getDockerContainerId();
        if (containerId == null) {
            return;
        }
        executor.submit(() -> {
            try {
                if (instance.isNativeCloudInit()) {
                    execInContainerForResult(containerId,
                            new String[]{"rm", "-f", SYSTEMD_RELEASE_PATH}, 5);
                }
                dockerClient.restartContainerCmd(containerId).exec();
                String instanceId = instance.getInstanceId();
                ContainerNetworkAddress containerAddress = waitForContainerNetworkAddress(containerId, instanceId);
                String containerIp = containerAddress != null ? containerAddress.ipAddress() : null;
                if (containerIp == null || containerIp.isBlank()) {
                    cleanupFailedLaunch(instance, containerId, instance.getContainerBridgeIp(), instance.getSshHostPort());
                    return;
                }
                instance.setContainerBridgeIp(containerIp);
                exposeReachableNetworkAddress(instance, containerAddress);
                metadataServer.registerContainer(containerIp, instanceId, instance);
                String flociHost = dockerHostResolver.resolve();
                int imdsPort = config.services().ec2().imdsPort();
                boolean metadataReady = instance.isNativeCloudInit()
                        ? configureNativeCloudInitMetadata(containerId, instanceId, flociHost, imdsPort)
                        : configureLinkLocalMetadataEndpoint(containerId, instanceId, flociHost, imdsPort);
                if (!metadataReady) {
                    cleanupFailedLaunch(instance, containerId, containerIp, instance.getSshHostPort());
                    return;
                }
                LOG.infov("Rebooted EC2 container {0}", containerId);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                LOG.warnv("Error rebooting EC2 container {0}: {1}", containerId, e.getMessage());
            }
        });
    }

    public boolean isContainerRunning(Instance instance) {
        String containerId = instance.getDockerContainerId();
        return containerId != null && lifecycleManager.isContainerRunning(containerId);
    }

    private void injectSshKey(String containerId, String publicKey) {
        try {
            // Ensure .ssh directory exists with correct permissions
            execInContainer(containerId, new String[]{"sh", "-c",
                    "mkdir -p /root/.ssh && chmod 700 /root/.ssh"}, 10);

            // Copy authorized_keys via docker cp
            String keyContent = publicKey.trim() + "\n";
            byte[] tar = buildSingleFileTar("authorized_keys", keyContent.getBytes(StandardCharsets.UTF_8), 0600);
            dockerClient.copyArchiveToContainerCmd(containerId)
                    .withRemotePath("/root/.ssh")
                    .withTarInputStream(new ByteArrayInputStream(tar))
                    .exec();

            execInContainer(containerId, new String[]{"chmod", "600", "/root/.ssh/authorized_keys"}, 5);
            LOG.infov("Injected SSH public key into container {0}", containerId);
        } catch (Exception e) {
            LOG.warnv("Could not inject SSH key into container {0}: {1}", containerId, e.getMessage());
        }
    }

    private void startSshd(String containerId, String instanceId) {
        try {
            // Install openssh-server if absent
            execInContainer(containerId, new String[]{"sh", "-c",
                    "if ! command -v sshd >/dev/null 2>&1; then" +
                    "  if command -v dnf >/dev/null 2>&1; then dnf install -y openssh-server >/dev/null 2>&1;" +
                    "  elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server >/dev/null 2>&1;" +
                    "  elif command -v apk >/dev/null 2>&1; then apk add --no-cache openssh >/dev/null 2>&1;" +
                    "  fi;" +
                    "fi"}, 120);
            // Generate host keys
            execInContainer(containerId, new String[]{"ssh-keygen", "-A"}, 10);
            // Start sshd without -D so it daemonizes itself and survives this exec session
            execInContainer(containerId, new String[]{"/usr/sbin/sshd"}, 5);
            LOG.infov("Started sshd in EC2 instance {0}", instanceId);
        } catch (Exception e) {
            LOG.warnv("Could not start sshd in EC2 instance {0}: {1}", instanceId, e.getMessage());
        }
    }

    private void executeUserData(String containerId, String instanceId, String userData, String region) {
        try {
            String logGroup = "/aws/ec2/" + instanceId;
            String logStream = logStreamer.generateLogStreamName("user-data");

            List<String> shellScripts = userDataShellScripts(userData);
            if (shellScripts.isEmpty()) {
                LOG.infov("UserData for EC2 instance {0} did not contain executable shellscript parts", instanceId);
                return;
            }

            // Execute the script and stream output to CloudWatch
            for (int i = 0; i < shellScripts.size(); i++) {
                executeUserDataShellScript(
                    containerId, instanceId, shellScripts.get(i), i + 1, shellScripts.size(),
                    logGroup, logStream, region
                );
            }
        } catch (Exception e) {
            LOG.warnv("UserData execution failed for EC2 instance {0}: {1}", instanceId, e.getMessage());
        }
    }

    private void executeUserDataShellScript(
        String containerId, String instanceId, String scriptContent, int partNumber, int partCount,
        String logGroup, String logStream, String region
    ) throws Exception {
        byte[] script = scriptContent.getBytes(StandardCharsets.UTF_8);
        byte[] tar = buildSingleFileTar("user-data.sh", script, 0755);
        dockerClient.copyArchiveToContainerCmd(containerId)
                .withRemotePath("/tmp")
                .withTarInputStream(new ByteArrayInputStream(tar))
                .exec();

        // Execute the script directly so Docker honors its shebang, matching cloud-init shellscript behavior.
        String execId = dockerClient.execCreateCmd(containerId)
                .withCmd(userDataExecutionCommand())
                .withAttachStdout(true)
                .withAttachStderr(true)
                .exec()
                .getId();

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        CountDownLatch latch = new CountDownLatch(1);

        dockerClient.execStartCmd(execId).exec(new ResultCallback.Adapter<Frame>() {
            @Override
            public void onNext(Frame frame) {
                byte[] payload = frame.getPayload();
                if (payload == null) return;
                try { output.write(payload); } catch (IOException ignored) {}
                String line = new String(payload, StandardCharsets.UTF_8).stripTrailing();
                if (!line.isEmpty()) {
                    logStreamer.streamToCloudWatchLogs(logGroup, logStream, region, line);
                }
            }
            @Override
            public void onComplete() { latch.countDown(); }
            @Override
            public void onError(Throwable t) { latch.countDown(); }
        });

        boolean completed = latch.await(30, TimeUnit.MINUTES);
        if (!completed) {
            LOG.warnv("UserData shellscript part {0}/{1} timed out for EC2 instance {2}", partNumber, partCount, instanceId);
            return;
        }

        Long exitCode = dockerClient.inspectExecCmd(execId).exec().getExitCodeLong();
        if (exitCode != null && exitCode != 0) {
            LOG.warnv("UserData shellscript part {0}/{1} failed for EC2 instance {2} with exit code {3}: {4}",
                    partNumber, partCount, instanceId, exitCode, summarizeUserDataOutput(output));
            return;
        }

        LOG.infov("UserData shellscript part {0}/{1} completed for EC2 instance {2}: {3}",
                partNumber, partCount, instanceId, summarizeUserDataOutput(output));
    }

    static List<String> userDataShellScripts(String userData) {
        if (userData == null || userData.isBlank()) {
            return List.of();
        }

        String normalized = userData.replace("\r\n", "\n").replace('\r', '\n');
        String trimmed = normalized.stripLeading();
        if (trimmed.startsWith("#!")) {
            return List.of(normalized);
        }

        Matcher matcher = MIME_BOUNDARY.matcher(normalized);
        if (!matcher.find()) {
            return List.of();
        }

        String boundary = matcher.group(1).trim();
        if (boundary.isEmpty()) {
            return List.of();
        }

        List<String> scripts = new ArrayList<>();
        String marker = "--" + boundary;
        for (String segment : normalized.split(Pattern.quote(marker))) {
            String part = segment.stripLeading();
            if (part.isBlank() || part.startsWith("--")) {
                continue;
            }
            int headerEnd = part.indexOf("\n\n");
            if (headerEnd < 0) {
                continue;
            }
            String headers = part.substring(0, headerEnd);
            String body = part.substring(headerEnd + 2);
            if (hasShellscriptContentType(headers)) {
                scripts.add(body.stripTrailing() + "\n");
            }
        }
        return List.copyOf(scripts);
    }

    static String userDataExecutionText(Ec2UserData userData) {
        byte[] bytes = userData.bytes();
        if (bytes.length < 2 || bytes[0] != 0x1f || bytes[1] != (byte) 0x8b) {
            return userData.utf8Text();
        }

        try (GzipCompressorInputStream gzip = GzipCompressorInputStream.builder()
                .setInputStream(new ByteArrayInputStream(bytes))
                .setDecompressConcatenated(true)
                .get()) {
            return new String(gzip.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOG.debugv("UserData has an invalid gzip payload; preserving prior execution materialization ({0} bytes)", bytes.length);
            return userData.utf8Text();
        }
    }

    private static boolean hasShellscriptContentType(String headers) {
        for (String line : headers.split("\n")) {
            String lower = line.toLowerCase(Locale.ROOT).strip();
            if (lower.startsWith("content-type:") && lower.contains("text/x-shellscript")) {
                return true;
            }
        }
        return false;
    }

    static String[] userDataExecutionCommand() {
        return new String[]{USER_DATA_SCRIPT_PATH};
    }

    static String[] metadataProxyInstallCommand() {
        return new String[]{"sh", "-c", String.join("\n",
                "set -eu",
                "if command -v ip >/dev/null 2>&1 && command -v socat >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then exit 0; fi",
                "if command -v apt-get >/dev/null 2>&1; then",
                "  apt-get update -qq >/dev/null",
                "  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 socat curl ca-certificates >/dev/null",
                "elif command -v dnf >/dev/null 2>&1; then",
                "  dnf install -y iproute socat curl ca-certificates >/dev/null",
                "elif command -v apk >/dev/null 2>&1; then",
                "  apk add --no-cache iproute2 socat curl ca-certificates >/dev/null",
                "else",
                "  echo 'No supported package manager found for IMDS proxy dependencies' >&2",
                "  exit 1",
                "fi")};
    }

    static String[] nativeMetadataProxyInstallCommand() {
        return new String[]{"sh", "-c", String.join("\n",
                "set -eu",
                "if command -v ip >/dev/null 2>&1 && command -v nc >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then exit 0; fi",
                "if command -v apt-get >/dev/null 2>&1; then",
                "  apt-get update -qq >/dev/null",
                "  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 netcat-openbsd curl ca-certificates >/dev/null",
                "elif command -v dnf >/dev/null 2>&1; then",
                "  dnf install -y iproute nmap-ncat curl ca-certificates >/dev/null",
                "elif command -v apk >/dev/null 2>&1; then",
                "  apk add --no-cache iproute2 netcat-openbsd curl ca-certificates >/dev/null",
                "else",
                "  echo 'No supported package manager found for native IMDS proxy dependencies' >&2",
                "  exit 1",
                "fi")};
    }

    static String[] metadataProxyStartCommand(String flociHost, int imdsPort) {
        return new String[]{"sh", "-c", String.join("\n",
                "set -eu",
                "ip addr show dev lo | grep -q '169.254.169.254/32' || ip addr add 169.254.169.254/32 dev lo",
                "if [ -f /tmp/floci-imds-proxy.pid ] && kill -0 \"$(cat /tmp/floci-imds-proxy.pid)\" 2>/dev/null; then",
                "  exit 0",
                "fi",
                "nohup socat TCP-LISTEN:80,bind=169.254.169.254,fork,reuseaddr TCP:" + flociHost + ":" + imdsPort + " >/tmp/floci-imds-proxy.log 2>&1 &",
                "echo $! > /tmp/floci-imds-proxy.pid",
                "for i in 1 2 3 4 5 6 7 8 9 10 11 12; do",
                "  curl -fsS --max-time 1 http://169.254.169.254/latest/meta-data/instance-id >/dev/null && exit 0",
                "  sleep 1",
                "done",
                "cat /tmp/floci-imds-proxy.log >&2 || true",
                "exit 1")};
    }

    static List<String> localAwsEnvironment(Instance instance, String region, String serviceEndpoint, String imdsEndpoint) {
        List<String> environment = new ArrayList<>(List.of(
                "AWS_EC2_METADATA_SERVICE_ENDPOINT=" + imdsEndpoint,
                "AWS_ENDPOINT_URL=" + serviceEndpoint,
                "AWS_DEFAULT_REGION=" + region,
                "AWS_REGION=" + region));
        if (instance.getIamInstanceProfileArn() == null || instance.getIamInstanceProfileArn().isBlank()) {
            environment.addAll(List.of(
                "AWS_ACCESS_KEY_ID=test",
                "AWS_SECRET_ACCESS_KEY=test",
                "AWS_SESSION_TOKEN=test-session-token"));
        }
        return List.copyOf(environment);
    }

    private static String summarizeUserDataOutput(ByteArrayOutputStream output) {
        String text = output.toString(StandardCharsets.UTF_8).stripTrailing();
        if (text.isBlank()) {
            return "(no output)";
        }
        int start = Math.max(0, text.length() - 2048);
        return text.substring(start);
    }

    private void installPreSystemdEntrypoint(String containerId) throws IOException {
        copyFileToContainer(containerId, "/usr/local/sbin", "floci-ec2-pre-systemd",
                preSystemdEntrypoint().getBytes(StandardCharsets.UTF_8), 0755);
    }

    private boolean configureNativeCloudInitMetadata(
            String containerId, String instanceId, String flociHost, int imdsPort) {
        try {
            ContainerExecResult install = execInContainerForResult(
                    containerId, nativeMetadataProxyInstallCommand(), metadataProxyInstallTimeoutSeconds);
            if (install.exitCode() != 0) {
                LOG.warnv("Could not install native cloud-init IMDS dependencies for EC2 instance {0}: {1}",
                        instanceId, install.summary());
                return false;
            }

            copyFileToContainer(containerId, "/etc/systemd/system", "floci-imds-address.service",
                    metadataAddressUnit().getBytes(StandardCharsets.UTF_8), 0644);
            copyFileToContainer(containerId, "/etc/systemd/system", "floci-imds-proxy.socket",
                    metadataProxySocketUnit().getBytes(StandardCharsets.UTF_8), 0644);
            copyFileToContainer(containerId, "/etc/systemd/system", "floci-imds-proxy@.service",
                    metadataProxyServiceUnit(flociHost, imdsPort).getBytes(StandardCharsets.UTF_8), 0644);
            copyFileToContainer(containerId, "/etc/cloud", "ds-identify.cfg",
                    cloudInitDatasourceIdentification().getBytes(StandardCharsets.UTF_8), 0644);
            copyFileToContainer(containerId, "/etc/cloud/cloud.cfg.d", "99-floci-ec2.cfg",
                    cloudInitDatasourceConfiguration().getBytes(StandardCharsets.UTF_8), 0644);

            ContainerExecResult enable = execInContainerForResult(containerId,
                    new String[]{"systemctl", "enable", "floci-imds-address.service", "floci-imds-proxy.socket"}, 15);
            if (enable.exitCode() != 0) {
                LOG.warnv("Could not enable native cloud-init IMDS units for EC2 instance {0}: {1}",
                        instanceId, enable.summary());
                return false;
            }

            ContainerExecResult metadata = execInContainerForResult(containerId,
                    new String[]{"curl", "-fsS", "--max-time", "2",
                            "http://" + flociHost + ":" + imdsPort + "/latest/meta-data/instance-id"}, 5);
            if (metadata.exitCode() != 0 || !instanceId.equals(metadata.output().strip())) {
                LOG.warnv("Native cloud-init IMDS preflight failed for EC2 instance {0}: {1}",
                        instanceId, metadata.summary());
                return false;
            }

            ContainerExecResult release = execInContainerForResult(containerId,
                    new String[]{"sh", "-c", "mkdir -p /run/floci-ec2 && touch " + SYSTEMD_RELEASE_PATH}, 5);
            if (release.exitCode() != 0) {
                LOG.warnv("Could not release systemd boot for EC2 instance {0}: {1}",
                        instanceId, release.summary());
                return false;
            }

            LOG.infov("Released native cloud-init boot for EC2 instance {0} after IMDS preflight", instanceId);
            return true;
        }
        catch (Exception e) {
            LOG.warnv("Could not configure native cloud-init IMDS for EC2 instance {0}: {1}",
                    instanceId, e.getMessage());
            return false;
        }
    }

    static String preSystemdEntrypoint() {
        return String.join("\n",
                "#!/bin/sh",
                "set -eu",
                "mkdir -p /run/floci-ec2",
                "while [ ! -e " + SYSTEMD_RELEASE_PATH + " ]; do sleep 0.05; done",
                "rm -f " + SYSTEMD_RELEASE_PATH,
                "exec \"$@\"",
                "");
    }

    static String metadataAddressUnit() {
        return """
                [Unit]
                Description=Configure the EC2 instance metadata address
                DefaultDependencies=no
                Before=floci-imds-proxy.socket cloud-init-local.service

                [Service]
                Type=oneshot
                ExecStart=-/usr/sbin/ip address add 169.254.169.254/32 dev lo
                RemainAfterExit=yes

                [Install]
                WantedBy=cloud-init-local.service
                """;
    }

    static String metadataProxySocketUnit() {
        return """
                [Unit]
                Description=EC2 instance metadata proxy socket
                DefaultDependencies=no
                Requires=floci-imds-address.service
                After=floci-imds-address.service
                Before=cloud-init-local.service

                [Socket]
                ListenStream=169.254.169.254:80
                FreeBind=true
                Accept=yes

                [Install]
                WantedBy=cloud-init-local.service
                """;
    }

    static String metadataProxyServiceUnit(String flociHost, int imdsPort) {
        if (flociHost == null || !flociHost.matches("[A-Za-z0-9._:-]+")) {
            throw new IllegalArgumentException("Invalid Docker host for EC2 metadata proxy");
        }
        return """
                [Unit]
                Description=EC2 instance metadata proxy connection
                DefaultDependencies=no
                After=floci-imds-address.service

                [Service]
                ExecStart=/usr/bin/nc %s %d
                StandardInput=socket
                StandardOutput=socket
                """.formatted(flociHost, imdsPort);
    }

    static String cloudInitDatasourceIdentification() {
        return """
                datasource: Ec2
                policy: enabled
                """;
    }

    static String cloudInitDatasourceConfiguration() {
        return """
                datasource_list: [ Ec2 ]
                datasource:
                  Ec2:
                    metadata_urls: [ "http://169.254.169.254" ]
                    max_wait: 60
                    timeout: 5
                    strict_id: false
                """;
    }

    private void copyFileToContainer(
            String containerId, String directory, String filename, byte[] content, int mode) throws IOException {
        dockerClient.copyArchiveToContainerCmd(containerId)
                .withRemotePath(directory)
                .withTarInputStream(new ByteArrayInputStream(buildSingleFileTar(filename, content, mode)))
                .exec();
    }

    private boolean configureLinkLocalMetadataEndpoint(String containerId, String instanceId, String flociHost, int imdsPort) {
        try {
            ContainerExecResult install = execInContainerForResult(containerId, metadataProxyInstallCommand(), metadataProxyInstallTimeoutSeconds);
            if (install.exitCode() != 0) {
                LOG.warnv("Could not install IMDS proxy dependencies for EC2 instance {0}: {1}",
                        instanceId, install.summary());
                return false;
            }

            ContainerExecResult start = execInContainerForResult(containerId, metadataProxyStartCommand(flociHost, imdsPort), 30);
            if (start.exitCode() != 0) {
                LOG.warnv("Could not start link-local IMDS proxy for EC2 instance {0}: {1}",
                        instanceId, start.summary());
                return false;
            }

            LOG.infov("Configured link-local IMDS endpoint for EC2 instance {0}", instanceId);
            return true;
        } catch (Exception e) {
            LOG.warnv("Could not configure link-local IMDS endpoint for EC2 instance {0}: {1}", instanceId, e.getMessage());
            return false;
        }
    }

    private void cleanupFailedLaunch(Instance instance, String containerId, String containerIp, int sshHostPort) {
        portForwardManager.unpublishAll(instance);
        lifecycleManager.stopAndRemove(containerId, null);
        if (sshHostPort > 0) {
            portAllocator.release(sshHostPort);
        }
        metadataServer.unregisterContainer(containerIp, instance);
        instance.setState(InstanceState.terminated());
        instance.setTerminatedAt(System.currentTimeMillis());
    }

    private void execInContainer(String containerId, String[] cmd, int timeoutSeconds) throws Exception {
        execInContainerForResult(containerId, cmd, timeoutSeconds);
    }

    private ContainerExecResult execInContainerForResult(String containerId, String[] cmd, int timeoutSeconds) throws Exception {
        String execId = dockerClient.execCreateCmd(containerId)
                .withCmd(cmd)
                .withAttachStdout(true)
                .withAttachStderr(true)
                .exec()
                .getId();

        CountDownLatch latch = new CountDownLatch(1);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ResultCallback.Adapter<Frame> callback = new ResultCallback.Adapter<Frame>() {
            @Override
            public void onNext(Frame frame) {
                if (frame.getPayload() != null) {
                    try { output.write(frame.getPayload()); } catch (IOException ignored) {}
                }
            }
            @Override
            public void onComplete() { latch.countDown(); }
            @Override
            public void onError(Throwable t) { latch.countDown(); }
        };
        try (callback) {
            dockerClient.execStartCmd(execId).exec(callback);
            boolean completed = latch.await(timeoutSeconds, TimeUnit.SECONDS);
            if (!completed) {
                return new ContainerExecResult(-1, "Timed out after " + timeoutSeconds + "s");
            }
        }
        Long exitCode = dockerClient.inspectExecCmd(execId).exec().getExitCodeLong();
        return new ContainerExecResult(exitCode != null ? exitCode : -1, summarizeUserDataOutput(output));
    }

    record ContainerExecResult(long exitCode, String output) {
        String summary() {
            return output == null || output.isBlank() ? "(no output)" : output;
        }
    }

    private ContainerNetworkAddress getContainerNetworkAddress(String containerId) {
        try {
            var inspect = dockerClient.inspectContainerCmd(containerId).exec();
            if (inspect.getNetworkSettings() != null) {
                var networks = inspect.getNetworkSettings().getNetworks();
                if (networks != null) {
                    Optional<ContainerNetworkAddress> preferredAddress = preferredMetadataSourceAddress(networks);
                    if (preferredAddress.isPresent()) {
                        return preferredAddress.get();
                    }
                }
                String ip = inspect.getNetworkSettings().getIpAddress();
                if (ip != null && !ip.isBlank()) {
                    return new ContainerNetworkAddress(ip, inspect.getNetworkSettings().getMacAddress());
                }
            }
        } catch (Exception e) {
            LOG.warnv("Could not inspect container {0} for bridge IP: {1}", containerId, e.getMessage());
        }
        return null;
    }

    private ContainerNetworkAddress waitForContainerNetworkAddress(String containerId, String instanceId)
            throws InterruptedException {
        for (int i = 0; i < containerBridgeIpAttempts; i++) {
            ContainerNetworkAddress address = getContainerNetworkAddress(containerId);
            if (address != null && address.ipAddress() != null && !address.ipAddress().isBlank()) {
                return address;
            }
            Thread.sleep(containerBridgeIpPollMillis);
        }
        LOG.warnv("Timed out waiting for EC2 instance {0} container {1} bridge IP", instanceId, containerId);
        return null;
    }

    static Optional<String> preferredMetadataSourceIp(Map<String, ContainerNetwork> networks) {
        return preferredMetadataSourceAddress(networks).map(ContainerNetworkAddress::ipAddress);
    }

    static Optional<ContainerNetworkAddress> preferredMetadataSourceAddress(Map<String, ContainerNetwork> networks) {
        if (networks == null || networks.isEmpty()) {
            return Optional.empty();
        }
        Optional<ContainerNetworkAddress> configuredNetworkAddress = networks.entrySet().stream()
                .filter(entry -> !"bridge".equals(entry.getKey()))
                .map(Map.Entry::getValue)
                .filter(network -> network.getIpAddress() != null && !network.getIpAddress().isBlank())
                .map(network -> new ContainerNetworkAddress(network.getIpAddress(), network.getMacAddress()))
                .findFirst();
        if (configuredNetworkAddress.isPresent()) {
            return configuredNetworkAddress;
        }
        ContainerNetwork bridge = networks.get("bridge");
        if (bridge != null && bridge.getIpAddress() != null && !bridge.getIpAddress().isBlank()) {
            return Optional.of(new ContainerNetworkAddress(bridge.getIpAddress(), bridge.getMacAddress()));
        }
        return networks.values().stream()
                .filter(network -> network.getIpAddress() != null && !network.getIpAddress().isBlank())
                .map(network -> new ContainerNetworkAddress(network.getIpAddress(), network.getMacAddress()))
                .findFirst();
    }

    record ContainerNetworkAddress(String ipAddress, String macAddress) {}

    private byte[] buildSingleFileTar(String filename, byte[] content, int mode) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (TarArchiveOutputStream tar = new TarArchiveOutputStream(bos)) {
            tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
            TarArchiveEntry entry = new TarArchiveEntry(filename);
            entry.setSize(content.length);
            entry.setMode(mode);
            tar.putArchiveEntry(entry);
            tar.write(content);
            tar.closeArchiveEntry();
        }
        return bos.toByteArray();
    }
}
