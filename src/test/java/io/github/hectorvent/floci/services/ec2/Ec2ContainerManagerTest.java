package io.github.hectorvent.floci.services.ec2;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.CopyArchiveToContainerCmd;
import com.github.dockerjava.api.command.ExecCreateCmd;
import com.github.dockerjava.api.command.ExecCreateCmdResponse;
import com.github.dockerjava.api.command.ExecStartCmd;
import com.github.dockerjava.api.command.InspectContainerCmd;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.command.InspectExecCmd;
import com.github.dockerjava.api.command.InspectExecResponse;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.NetworkSettings;
import com.github.dockerjava.api.model.StreamType;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.ec2.portforward.Ec2PortForwardManager;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import io.github.hectorvent.floci.core.common.docker.DockerHostResolver;
import io.github.hectorvent.floci.core.common.docker.PortAllocator;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.InstanceNetworkInterface;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Answers.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

class Ec2ContainerManagerTest {

    private static final String TEST_USER_DATA_OUTPUT = "test-output";
    private static final String TEST_CONTAINER_ID = "container-1";

    @org.junit.jupiter.api.AfterEach
    void resetBridgeIpPolling() {
        Ec2ContainerManager.containerBridgeIpAttempts = 30;
        Ec2ContainerManager.containerBridgeIpPollMillis = 500;
        Ec2ContainerManager.metadataProxyInstallTimeoutSeconds = 180;
    }

    @Test
    void exposeReachablePrivateAddressUpdatesInstanceAndAttachedNetworkInterfaces() {
        Instance instance = new Instance();
        instance.setPrivateIpAddress("10.82.32.10");
        instance.setPrivateDnsName("ip-10-82-32-10.ec2.internal");

        InstanceNetworkInterface networkInterface = new InstanceNetworkInterface();
        networkInterface.setPrivateIpAddress("10.82.32.10");
        networkInterface.setPrivateDnsName("ip-10-82-32-10.ec2.internal");
        instance.setNetworkInterfaces(List.of(networkInterface));

        Ec2ContainerManager.exposeReachablePrivateAddress(instance, "192.168.215.21");

        assertEquals("192.168.215.21", instance.getPrivateIpAddress());
        assertEquals("ip-192-168-215-21.ec2.internal", instance.getPrivateDnsName());
        assertEquals("192.168.215.21", networkInterface.getPrivateIpAddress());
        assertEquals("ip-192-168-215-21.ec2.internal", networkInterface.getPrivateDnsName());
    }

    @Test
    void exposeReachableNetworkAddressUpdatesAttachedInterfaceMac() {
        Instance instance = new Instance();
        InstanceNetworkInterface networkInterface = new InstanceNetworkInterface();
        instance.setNetworkInterfaces(new ArrayList<>(List.of(networkInterface)));

        Ec2ContainerManager.exposeReachableNetworkAddress(
                instance,
                new Ec2ContainerManager.ContainerNetworkAddress("192.168.215.21", "02:42:ac:11:00:15"));

        assertEquals("02:42:ac:11:00:15", networkInterface.getMacAddress());
    }

    @Test
    void restoreMetadataRegistrationRegistersRunningPersistedContainer() {
        ContainerLifecycleManager lifecycleManager = mock(ContainerLifecycleManager.class);
        when(lifecycleManager.isContainerRunning(TEST_CONTAINER_ID)).thenReturn(true);

        DockerClient dockerClient = mock(DockerClient.class);
        InspectContainerCmd inspect = mock(InspectContainerCmd.class);
        InspectContainerResponse response = inspectResponse("192.168.215.42");
        when(dockerClient.inspectContainerCmd(TEST_CONTAINER_ID)).thenReturn(inspect);
        when(inspect.exec()).thenReturn(response);

        Ec2MetadataServer metadataServer = mock(Ec2MetadataServer.class);
        Ec2ContainerManager manager = new Ec2ContainerManager(
                mock(ContainerBuilder.class),
                lifecycleManager,
                mock(ContainerDetector.class),
                mock(DockerHostResolver.class),
                dockerClient,
                mock(PortAllocator.class),
                mock(EmulatorConfig.class),
                metadataServer,
                mock(Ec2PortForwardManager.class));

        Instance instance = new Instance();
        instance.setInstanceId("i-restored");
        instance.setDockerContainerId(TEST_CONTAINER_ID);
        instance.setContainerBridgeIp("192.168.215.7");

        assertTrue(manager.restoreMetadataRegistration(instance));

        assertEquals("192.168.215.42", instance.getContainerBridgeIp());
        assertEquals("192.168.215.42", instance.getPrivateIpAddress());
        verify(metadataServer).unregisterContainer("192.168.215.7", instance);
        verify(metadataServer).registerContainer("192.168.215.42", "i-restored", instance);
    }

    @Test
    void terminateTearsDownInstanceMetadataCredentials() {
        LaunchHarness harness = launchHarness();
        Instance instance = instance("i-terminated");

        harness.manager.terminate(instance);

        verify(harness.metadataServer, timeout(1000)).unregisterInstance(instance);
    }

    @Test
    void userDataExecutionCommandUsesUniqueRuntimeFilesAndCleansThem() {
        String[] command = Ec2ContainerManager.userDataExecutionCommand(
                "/run/floci-ec2/user-data-123.sh", "/run/floci-ec2/user-data-123.pid");

        assertEquals("sh", command[0]);
        assertTrue(command[2].contains("setsid \"$script\""));
        assertTrue(command[2].contains("trap cleanup EXIT"));
        assertEquals("/run/floci-ec2/user-data-123.sh", command[4]);
        assertEquals("/run/floci-ec2/user-data-123.pid", command[5]);
    }

    @Test
    void userDataShellScriptsPreservesRawShellScript() {
        String script = "#!/bin/bash\nset -euo pipefail\necho ready\n";

        assertEquals(List.of(script), Ec2ContainerManager.userDataShellScripts(script));
    }

    @Test
    void userDataShellScriptsExtractsMimeShellscriptPartsInOrder() {
        String userData = """
                Content-Type: multipart/mixed; boundary="==SAMPLE-CLOUD-INIT=="
                MIME-Version: 1.0

                --==SAMPLE-CLOUD-INIT==
                Content-Type: text/cloud-config; charset="us-ascii"

                #cloud-config

                --==SAMPLE-CLOUD-INIT==
                Content-Type: text/x-shellscript; charset="us-ascii"

                #!/bin/bash
                echo first

                --==SAMPLE-CLOUD-INIT==
                Content-Type: text/x-shellscript

                #!/bin/sh
                echo second

                --==SAMPLE-CLOUD-INIT==--
                """;

        assertEquals(
                List.of(
                        "#!/bin/bash\necho first\n",
                        "#!/bin/sh\necho second\n"),
                Ec2ContainerManager.userDataShellScripts(userData));
    }

    @Test
    void userDataShellScriptsIgnoresCloudConfigWithoutShellscript() {
        String userData = """
                Content-Type: multipart/mixed; boundary=cloudinit
                MIME-Version: 1.0

                --cloudinit
                Content-Type: text/cloud-config

                #cloud-config

                --cloudinit--
                """;

        assertTrue(Ec2ContainerManager.userDataShellScripts(userData).isEmpty());
    }

    @Test
    void userDataExecutionTextDecompressesValidGzipShellScript() throws Exception {
        String script = "#!/bin/bash\nset -euo pipefail\necho ready\n";
        byte[] compressed = gzip(script);
        Ec2UserData userData = Ec2UserData.fromBytes(compressed);

        String materialized = Ec2ContainerManager.userDataExecutionText(userData);

        assertEquals(script, materialized);
        assertArrayEquals(compressed, userData.bytes());
        assertEquals(Base64.getEncoder().encodeToString(compressed), userData.encoded());
        assertEquals(List.of(script), Ec2ContainerManager.userDataShellScripts(materialized));
    }

    @Test
    void userDataExecutionTextPreservesPlainUtf8Text() {
        String script = "#!/bin/bash\r\nprintf 'ready \u03bb\\n'\r\n";

        assertEquals(script, Ec2ContainerManager.userDataExecutionText(Ec2UserData.fromText(script)));
    }

    @Test
    void userDataExecutionTextDoesNotApplyAdmissionLimitToExpandedGzip() throws Exception {
        String script = "#!/bin/bash\n# " + "a".repeat(Ec2UserData.MAX_DECODED_BYTES * 4) + "\necho ready\n";
        byte[] compressed = gzip(script);

        assertTrue(compressed.length <= Ec2UserData.MAX_DECODED_BYTES);
        assertTrue(script.getBytes(StandardCharsets.UTF_8).length > Ec2UserData.MAX_DECODED_BYTES);
        assertEquals(script, Ec2ContainerManager.userDataExecutionText(Ec2UserData.fromBytes(compressed)));
    }

    @Test
    void userDataExecutionTextDecompressesValidGzipMultipartBeforeExtraction() throws Exception {
        String multipart = """
                Content-Type: multipart/mixed; boundary=gzip-cloud-init
                MIME-Version: 1.0

                --gzip-cloud-init
                Content-Type: text/x-shellscript

                #!/bin/bash
                echo first

                --gzip-cloud-init
                Content-Type: text/x-shellscript

                #!/bin/sh
                echo second

                --gzip-cloud-init--
                """;

        String materialized = Ec2ContainerManager.userDataExecutionText(
                Ec2UserData.fromBytes(gzip(multipart)));

        assertEquals(multipart, materialized);
        assertEquals(
                List.of("#!/bin/bash\necho first\n", "#!/bin/sh\necho second\n"),
                Ec2ContainerManager.userDataShellScripts(materialized));
    }

    @Test
    void userDataExecutionTextPreservesPriorHandlingForInvalidGzip() {
        Ec2UserData userData = Ec2UserData.fromBytes(
                new byte[]{0x1f, (byte) 0x8b, 0x00, (byte) 0xff});

        assertEquals(userData.utf8Text(), Ec2ContainerManager.userDataExecutionText(userData));
        assertTrue(Ec2ContainerManager.userDataShellScripts(
                Ec2ContainerManager.userDataExecutionText(userData)).isEmpty());
    }

    @Test
    void userDataExecutionTextPreservesPriorHandlingForTrailingGarbage() throws Exception {
        byte[] gzip = gzip("#!/bin/bash\necho must-not-run\n");
        byte[] invalid = Arrays.copyOf(gzip, gzip.length + 1);
        invalid[invalid.length - 1] = 0x7f;
        Ec2UserData userData = Ec2UserData.fromBytes(invalid);

        assertEquals(userData.utf8Text(), Ec2ContainerManager.userDataExecutionText(userData));
        assertTrue(Ec2ContainerManager.userDataShellScripts(
                Ec2ContainerManager.userDataExecutionText(userData)).isEmpty());
    }

    @Test
    void launchPersistsSuccessfulRedactedUserDataResult() throws Exception {
        LaunchHarness harness = launchHarness();
        harness.stubSuccessfulExecs(new CountDownLatch(0), new CountDownLatch(0));
        AtomicReference<Instance> persisted = new AtomicReference<>();
        harness.manager.setInstancePersister(persisted::set);

        // manually set up container bridge IP
        InspectContainerCmd inspect = mock(InspectContainerCmd.class);
        InspectContainerResponse response = inspectResponse("192.168.215.42");
        when(harness.dockerClient.inspectContainerCmd(TEST_CONTAINER_ID)).thenReturn(inspect);
        when(inspect.exec()).thenReturn(response);

        String instanceId = "i-userdatacloudwatch";
        Instance instance = instance(instanceId);
        instance.setEncodedUserData(Ec2UserData.fromText("""
                #!/bin/bash
                echo test
                """).encoded());
        harness.manager.launch(instance, "ubuntu:24.04", null, "us-west-2");
        awaitUntil(() -> instance.getBootstrapResult() != null
                && "SUCCEEDED".equals(instance.getBootstrapResult().getStatus()), Duration.ofSeconds(2));

        assertEquals("User data completed", instance.getBootstrapResult().getMessage());
        assertFalse(instance.getBootstrapResult().getMessage().contains(TEST_USER_DATA_OUTPUT));
        assertEquals(instance, persisted.get());
    }

    @Test
    void launchInstanceExecutesGzipUserData() throws Exception {
        LaunchHarness harness = launchHarness();
        harness.stubSuccessfulExecs(new CountDownLatch(0), new CountDownLatch(0));
        AtomicReference<Instance> persisted = new AtomicReference<>();
        harness.manager.setInstancePersister(persisted::set);

        InspectContainerCmd inspect = mock(InspectContainerCmd.class);
        InspectContainerResponse response = inspectResponse("192.168.215.43");
        when(harness.dockerClient.inspectContainerCmd(TEST_CONTAINER_ID)).thenReturn(inspect);
        when(inspect.exec()).thenReturn(response);

        Instance instance = instance("i-gzip-userdata");
        instance.setEncodedUserData(Ec2UserData.fromBytes(gzip("""
                #!/bin/bash
                echo test
                """)).encoded());
        harness.manager.launch(instance, "ubuntu:24.04", null, "us-west-2");

        awaitUntil(() -> instance.getBootstrapResult() != null
                && "SUCCEEDED".equals(instance.getBootstrapResult().getStatus()), Duration.ofSeconds(2));
        assertEquals("User data completed", instance.getBootstrapResult().getMessage());
        assertFalse(instance.getBootstrapResult().getMessage().contains(TEST_USER_DATA_OUTPUT));
        assertEquals(instance, persisted.get());
    }

    @Test
    void metadataProxyInstallCommandInstallsLinkLocalProxyDependencies() {
        String[] command = Ec2ContainerManager.metadataProxyInstallCommand();

        assertEquals("sh", command[0]);
        assertTrue(command[2].contains("iproute2"));
        assertTrue(command[2].contains("socat"));
        assertTrue(command[2].contains("curl"));
    }

    @Test
    void nativeMetadataProxyInstallCommandUsesSocketActivatedProxyDependencies() {
        String[] command = Ec2ContainerManager.nativeMetadataProxyInstallCommand();

        assertEquals("sh", command[0]);
        assertTrue(command[2].contains("iproute2"));
        assertTrue(command[2].contains("netcat-openbsd"));
        assertTrue(command[2].contains("curl"));
        assertFalse(command[2].contains("command -v socat"));
    }

    @Test
    void metadataProxyStartCommandBindsAwsLinkLocalMetadataAddress() {
        String[] command = Ec2ContainerManager.metadataProxyStartCommand("floci", 9169);

        assertEquals("sh", command[0]);
        assertTrue(command[2].contains("169.254.169.254/32"));
        assertTrue(command[2].contains("TCP-LISTEN:80,bind=169.254.169.254"));
        assertTrue(command[2].contains("TCP:floci:9169"));
        assertTrue(command[2].contains("http://169.254.169.254/latest/meta-data/instance-id"));
        assertTrue(command[2].contains("/run/floci-ec2/imds-proxy.pid"));
        assertFalse(command[2].contains("/tmp/"));
    }

    @Test
    void localAwsEnvironmentProvidesCliCredentialsAndFlociEndpointWithoutInstanceProfile() {
        Instance instance = instance("i-no-profile");
        assertEquals(
                java.util.List.of(
                        "AWS_EC2_METADATA_SERVICE_ENDPOINT=http://floci:9169",
                        "AWS_ENDPOINT_URL=http://floci:4566",
                        "AWS_DEFAULT_REGION=us-west-2",
                        "AWS_REGION=us-west-2",
                        "AWS_ACCESS_KEY_ID=test",
                        "AWS_SECRET_ACCESS_KEY=test",
                        "AWS_SESSION_TOKEN=test-session-token"),
                Ec2ContainerManager.localAwsEnvironment(
                        instance,
                        "us-west-2",
                        "http://floci:4566",
                        "http://floci:9169"));
    }

    @Test
    void localAwsEnvironmentLetsInstanceProfileCredentialsResolveFromImds() {
        Instance instance = instance("i-profile");
        instance.setIamInstanceProfileArn("arn:aws:iam::000000000000:instance-profile/worker-profile");

        assertEquals(
                java.util.List.of(
                        "AWS_EC2_METADATA_SERVICE_ENDPOINT=http://floci:9169",
                        "AWS_ENDPOINT_URL=http://floci:4566",
                        "AWS_DEFAULT_REGION=us-west-2",
                        "AWS_REGION=us-west-2"),
                Ec2ContainerManager.localAwsEnvironment(
                        instance,
                        "us-west-2",
                        "http://floci:4566",
                        "http://floci:9169"));
    }

    @Test
    void launchSystemdGuestUsesInitInsteadOfTail() throws Exception {
        Ec2ContainerManager.containerBridgeIpAttempts = 1;
        Ec2ContainerManager.containerBridgeIpPollMillis = 1;
        LaunchHarness harness = launchHarness();
        InspectContainerCmd inspect = mock(InspectContainerCmd.class);
        InspectContainerResponse withIp = inspectResponse("172.18.0.11");
        when(harness.dockerClient.inspectContainerCmd(TEST_CONTAINER_ID)).thenReturn(inspect);
        when(inspect.exec()).thenReturn(withIp);
        harness.stubSuccessfulExecs(new CountDownLatch(0), new CountDownLatch(0));
        Instance instance = instance("i-systemd");
        instance.setIamInstanceProfileArn("arn:aws:iam::000000000000:instance-profile/worker-profile");

        harness.manager.launch(instance,
                new ResolvedAmiImage("floci/ami-ubuntu:24.04-arm64", ResolvedAmiImage.SYSTEMD_RUNTIME, true),
                null,
                "us-west-2");

        awaitUntil(() -> "running".equals(instance.getState().getName()), Duration.ofSeconds(2));
        verify(harness.builder).withEnv(List.of(
                "AWS_EC2_METADATA_SERVICE_ENDPOINT=http://floci:9169",
                "AWS_ENDPOINT_URL=http://floci:4566",
                "AWS_DEFAULT_REGION=us-west-2",
                "AWS_REGION=us-west-2"));
        verify(harness.builder).withCmd(List.of("/sbin/init"));
        verify(harness.builder).withEntrypoint(List.of("/usr/local/sbin/floci-ec2-pre-systemd"));
        verify(harness.builder).withCgroupnsMode("host");
        verify(harness.builder).withBind("/sys/fs/cgroup", "/sys/fs/cgroup");
    }

    @Test
    void launchCleansUpContainerAndSshPortWhenPreSystemdInstallFails() throws Exception {
        LaunchHarness harness = launchHarness();
        CopyArchiveToContainerCmd copy = mock(
                CopyArchiveToContainerCmd.class, withSettings().defaultAnswer(RETURNS_SELF));
        when(harness.dockerClient.copyArchiveToContainerCmd(TEST_CONTAINER_ID)).thenReturn(copy);
        when(copy.exec()).thenThrow(new IllegalStateException("copy failed"));
        Instance instance = instance("i-pre-systemd-failure");

        harness.manager.launch(instance,
                new ResolvedAmiImage("floci/ami-ubuntu:24.04-arm64", ResolvedAmiImage.SYSTEMD_RUNTIME, true),
                null,
                "us-west-2");

        awaitUntil(() -> "terminated".equals(instance.getState().getName()), Duration.ofSeconds(2));
        verify(harness.lifecycleManager).stopAndRemove(TEST_CONTAINER_ID, null);
        verify(harness.portAllocator).release(2201);
        verify(harness.portForwardManager).unpublishAll(instance);
        verify(harness.metadataServer).unregisterContainer(null, instance);
        verify(harness.lifecycleManager, never()).startCreated(anyString(), any(ContainerSpec.class));
        assertTrue(instance.getTerminatedAt() > 0, "failed launch should record termination time");
    }

    @Test
    void nativeCloudInitUnitsOrderManagedImdsBeforeDatasourceProbe() {
        assertTrue(Ec2ContainerManager.preSystemdEntrypoint().contains("exec \"$@\""));
        assertTrue(Ec2ContainerManager.preSystemdEntrypoint().contains("/run/floci-ec2/start-systemd"));
        assertTrue(Ec2ContainerManager.metadataAddressUnit().contains("Before=floci-imds-proxy.socket cloud-init-local.service"));
        assertTrue(Ec2ContainerManager.metadataProxySocketUnit().contains("Before=cloud-init-local.service"));
        assertTrue(Ec2ContainerManager.metadataProxySocketUnit().contains("Accept=yes"));
        assertTrue(Ec2ContainerManager.metadataProxyServiceUnit("floci", 9169)
                .contains("ExecStart=/usr/bin/nc floci 9169"));
        assertTrue(Ec2ContainerManager.metadataProxyServiceUnit("floci", 9169)
                .contains("DefaultDependencies=no"));
        assertTrue(Ec2ContainerManager.cloudInitDatasourceIdentification().contains("datasource: Ec2"));
        assertTrue(Ec2ContainerManager.cloudInitDatasourceConfiguration().contains("datasource_list: [ Ec2 ]"));
        assertTrue(Ec2ContainerManager.cloudInitDatasourceConfiguration().contains("strict_id: false"));
    }

    @Test
    void nativeCloudInitMetadataUnitRejectsUnsafeDockerHost() {
        assertThrows(IllegalArgumentException.class,
                () -> Ec2ContainerManager.metadataProxyServiceUnit("floci host", 9169));
    }

    @Test
    void preferredMetadataSourceIpUsesConfiguredNetworkBeforeBridge() {
        ContainerNetwork bridge = new ContainerNetwork();
        bridge.withIpv4Address("172.17.0.8");
        ContainerNetwork floci = new ContainerNetwork();
        floci.withIpv4Address("192.168.215.10");

        assertEquals(
                "192.168.215.10",
                Ec2ContainerManager.preferredMetadataSourceIp(Map.of(
                        "bridge", bridge,
                        "custom-floci-network", floci)).orElseThrow());
    }

    @Test
    void preferredMetadataSourceIpFallsBackToBridge() {
        ContainerNetwork bridge = new ContainerNetwork();
        bridge.withIpv4Address("172.17.0.8");

        assertEquals(
                "172.17.0.8",
                Ec2ContainerManager.preferredMetadataSourceIp(Map.of("bridge", bridge)).orElseThrow());
    }

    @Test
    void preferredMetadataSourceIpIsEmptyWithoutUsableAddress() {
        ContainerNetwork bridge = new ContainerNetwork();

        assertTrue(Ec2ContainerManager.preferredMetadataSourceIp(Map.of("bridge", bridge)).isEmpty());
    }

    @Test
    void launchWaitsForContainerBridgeIpBeforeRegisteringImds() throws Exception {
        Ec2ContainerManager.containerBridgeIpAttempts = 3;
        Ec2ContainerManager.containerBridgeIpPollMillis = 1;
        LaunchHarness harness = launchHarness();
        InspectContainerCmd inspect = mock(InspectContainerCmd.class);
        InspectContainerResponse noIp = inspectResponse(null);
        InspectContainerResponse withIp = inspectResponse("172.18.0.9");
        when(harness.dockerClient.inspectContainerCmd(TEST_CONTAINER_ID)).thenReturn(inspect);
        when(inspect.exec()).thenReturn(noIp).thenReturn(withIp);
        harness.stubSuccessfulExecs(new CountDownLatch(0), new CountDownLatch(0));

        Instance instance = instance("i-waitip");

        harness.manager.launch(instance, "ubuntu:24.04", null, "us-west-2");

        awaitUntil(() -> "running".equals(instance.getState().getName()), Duration.ofSeconds(2));
        assertEquals(TEST_CONTAINER_ID, instance.getDockerContainerId());
        assertEquals("172.18.0.9", instance.getContainerBridgeIp());
        assertEquals("172.18.0.9", instance.getPrivateIpAddress());
        verify(inspect, times(2)).exec();
        verify(harness.metadataServer).registerContainer("172.18.0.9", "i-waitip", instance);
    }

    @Test
    void launchTerminatesWhenContainerBridgeIpNeverAppears() throws Exception {
        Ec2ContainerManager.containerBridgeIpAttempts = 2;
        Ec2ContainerManager.containerBridgeIpPollMillis = 1;
        LaunchHarness harness = launchHarness();
        InspectContainerCmd inspect = mock(InspectContainerCmd.class);
        InspectContainerResponse noIp = inspectResponse(null);
        when(harness.dockerClient.inspectContainerCmd(TEST_CONTAINER_ID)).thenReturn(inspect);
        when(inspect.exec()).thenReturn(noIp);

        Instance instance = instance("i-noip");

        harness.manager.launch(instance, "ubuntu:24.04", null, "us-west-2");

        awaitUntil(() -> "terminated".equals(instance.getState().getName()), Duration.ofSeconds(2));
        assertEquals(TEST_CONTAINER_ID, instance.getDockerContainerId());
        verify(harness.metadataServer, never()).registerContainer(anyString(), anyString(), any());
    }

    @Test
    void launchFailureBeforeContainerCreationReleasesAllocatedPort() throws Exception {
        LaunchHarness harness = launchHarness();
        when(harness.lifecycleManager.create(any(ContainerSpec.class)))
                .thenThrow(new IllegalStateException("create failed"));
        Instance instance = instance("i-create-failure");

        harness.manager.launch(instance, "ubuntu:24.04", null, "us-west-2");

        awaitUntil(() -> "terminated".equals(instance.getState().getName()), Duration.ofSeconds(2));
        verify(harness.portAllocator).release(2201);
        verify(harness.portForwardManager).unpublishAll(instance);
        assertTrue(instance.getTerminatedAt() > 0);
    }

    @Test
    void launchMarksInstanceRunningBeforeUserDataCompletes() throws Exception {
        Ec2ContainerManager.containerBridgeIpAttempts = 2;
        Ec2ContainerManager.containerBridgeIpPollMillis = 1;
        LaunchHarness harness = launchHarness();
        InspectContainerCmd inspect = mock(InspectContainerCmd.class);
        InspectContainerResponse withIp = inspectResponse("172.18.0.10");
        when(harness.dockerClient.inspectContainerCmd(TEST_CONTAINER_ID)).thenReturn(inspect);
        when(inspect.exec()).thenReturn(withIp);
        CountDownLatch userDataStarted = new CountDownLatch(1);
        CountDownLatch finishUserData = new CountDownLatch(1);
        harness.stubSuccessfulExecs(userDataStarted, finishUserData);
        Instance instance = instance("i-userdata");
        instance.setUserData("#!/bin/sh\necho ready\n");

        harness.manager.launch(instance, "ubuntu:24.04", null, "us-west-2");

        assertTrue(userDataStarted.await(2, TimeUnit.SECONDS), "user data should start");
        assertEquals("running", instance.getState().getName());
        assertFalse(finishUserData.await(10, TimeUnit.MILLISECONDS), "user data should still be blocked");
        finishUserData.countDown();
        awaitUntil(() -> "running".equals(instance.getState().getName()), Duration.ofSeconds(2));
    }

    @Test
    void launchTerminatesContainerAndSkipsUserDataWhenMetadataInstallerTimesOut() throws Exception {
        Ec2ContainerManager.containerBridgeIpAttempts = 1;
        Ec2ContainerManager.containerBridgeIpPollMillis = 1;
        Ec2ContainerManager.metadataProxyInstallTimeoutSeconds = 0;
        LaunchHarness harness = launchHarness();
        InspectContainerCmd inspect = mock(InspectContainerCmd.class);
        InspectContainerResponse withIp = inspectResponse("172.18.0.12");
        when(harness.dockerClient.inspectContainerCmd(TEST_CONTAINER_ID)).thenReturn(inspect);
        when(inspect.exec()).thenReturn(withIp);
        harness.stubMetadataInstallerTimeout();
        Instance instance = instance("i-installer-timeout");
        instance.setUserData("#!/bin/sh\necho should-not-run\n");

        harness.manager.launch(instance, "ubuntu:24.04", null, "us-west-2");

        awaitUntil(() -> "terminated".equals(instance.getState().getName()), Duration.ofSeconds(2));
        verify(harness.lifecycleManager).stopAndRemove(TEST_CONTAINER_ID, null);
        verify(harness.portAllocator).release(2201);
        verify(harness.metadataServer).unregisterContainer("172.18.0.12", instance);
        verify(harness.portForwardManager).unpublishAll(instance);
        verify(harness.dockerClient, never()).copyArchiveToContainerCmd(TEST_CONTAINER_ID);
        assertTrue(instance.getTerminatedAt() > 0, "failed launch should record termination time");
    }

    private static LaunchHarness launchHarness() {
        ContainerBuilder containerBuilder = mock(ContainerBuilder.class);
        ContainerBuilder.Builder builder = mock(ContainerBuilder.Builder.class, withSettings().defaultAnswer(RETURNS_SELF));
        when(containerBuilder.newContainer(anyString())).thenReturn(builder);
        when(builder.build()).thenReturn(new ContainerSpec("ubuntu:24.04"));

        ContainerLifecycleManager lifecycleManager = mock(ContainerLifecycleManager.class);
        when(lifecycleManager.create(any(ContainerSpec.class))).thenReturn(TEST_CONTAINER_ID);
        when(lifecycleManager.isContainerRunning(TEST_CONTAINER_ID)).thenReturn(true);

        DockerHostResolver dockerHostResolver = mock(DockerHostResolver.class);
        when(dockerHostResolver.resolve()).thenReturn("floci");
        PortAllocator portAllocator = mock(PortAllocator.class);
        when(portAllocator.allocate(anyInt(), anyInt())).thenReturn(2201);

        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.Ec2ServiceConfig ec2 = mock(EmulatorConfig.Ec2ServiceConfig.class);
        when(config.services()).thenReturn(services);
        when(services.ec2()).thenReturn(ec2);
        when(ec2.sshPortRangeStart()).thenReturn(2200);
        when(ec2.sshPortRangeEnd()).thenReturn(2299);
        when(ec2.imdsPort()).thenReturn(9169);
        when(ec2.userDataTimeoutSeconds()).thenReturn(30);

        DockerClient dockerClient = mock(DockerClient.class);
        Ec2MetadataServer metadataServer = mock(Ec2MetadataServer.class);
        Ec2PortForwardManager portForwardManager = mock(Ec2PortForwardManager.class);
        Ec2ContainerManager manager = new Ec2ContainerManager(
                containerBuilder,
                lifecycleManager,
                mock(ContainerDetector.class),
                dockerHostResolver,
                dockerClient,
                portAllocator,
                config,
                metadataServer,
                portForwardManager);
        return new LaunchHarness(manager, dockerClient, metadataServer, builder,
                lifecycleManager, portAllocator, portForwardManager);
    }

    private static Instance instance(String instanceId) {
        Instance instance = new Instance();
        instance.setInstanceId(instanceId);
        return instance;
    }

    private static InspectContainerResponse inspectResponse(String ipAddress) {
        InspectContainerResponse inspect = mock(InspectContainerResponse.class);
        NetworkSettings networkSettings = mock(NetworkSettings.class);
        when(inspect.getNetworkSettings()).thenReturn(networkSettings);
        if (ipAddress != null) {
            ContainerNetwork bridge = new ContainerNetwork().withIpv4Address(ipAddress);
            when(networkSettings.getNetworks()).thenReturn(Map.of("bridge", bridge));
        }
        return inspect;
    }

    private static void awaitUntil(BooleanSupplier condition, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(10);
        }
        assertTrue(condition.getAsBoolean(), "condition was not met before timeout");
    }

    private static byte[] gzip(String value) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) {
            gzip.write(value.getBytes(StandardCharsets.UTF_8));
        }
        return output.toByteArray();
    }

    private record LaunchHarness(Ec2ContainerManager manager,
                                 DockerClient dockerClient,
                                 Ec2MetadataServer metadataServer,
                                 ContainerBuilder.Builder builder,
                                 ContainerLifecycleManager lifecycleManager,
                                 PortAllocator portAllocator,
                                 Ec2PortForwardManager portForwardManager) {
        void stubMetadataInstallerTimeout() throws Exception {
            ExecCreateCmd execCreate = mock(ExecCreateCmd.class, withSettings().defaultAnswer(RETURNS_SELF));
            ExecCreateCmdResponse metadataExec = mock(ExecCreateCmdResponse.class);
            when(metadataExec.getId()).thenReturn("metadata-install-exec");
            when(dockerClient.execCreateCmd(TEST_CONTAINER_ID)).thenReturn(execCreate);
            when(execCreate.exec()).thenReturn(metadataExec);

            ExecStartCmd execStart = mock(ExecStartCmd.class);
            when(dockerClient.execStartCmd("metadata-install-exec")).thenReturn(execStart);
            when(execStart.exec(any())).thenAnswer(invocation -> invocation.getArgument(0));
        }

        void stubSuccessfulExecs(CountDownLatch userDataStarted, CountDownLatch finishUserData) throws Exception {
            AtomicReference<String[]> currentCommand = new AtomicReference<>();
            ExecCreateCmd execCreate = mock(ExecCreateCmd.class, withSettings().defaultAnswer(RETURNS_SELF));
            ExecCreateCmdResponse metadataExec = mock(ExecCreateCmdResponse.class);
            ExecCreateCmdResponse userDataExec = mock(ExecCreateCmdResponse.class);
            when(metadataExec.getId()).thenReturn("metadata-exec");
            when(userDataExec.getId()).thenReturn("userdata-exec");
            when(dockerClient.execCreateCmd(TEST_CONTAINER_ID)).thenReturn(execCreate);
            when(execCreate.withCmd(any(String[].class))).thenAnswer(invocation -> {
                Object[] args = invocation.getArguments();
                if (args.length == 1 && args[0] instanceof String[] command) {
                    currentCommand.set(command);
                } else {
                    currentCommand.set(Arrays.copyOf(args, args.length, String[].class));
                }
                return execCreate;
            });
            when(execCreate.exec()).thenAnswer(invocation -> {
                String[] command = currentCommand.get();
                if (command != null && command.length > 3 && "floci-user-data".equals(command[3])) {
                    return userDataExec;
                }
                return metadataExec;
            });

            when(dockerClient.execStartCmd(anyString())).thenAnswer(invocation -> {
                String execId = invocation.getArgument(0);
                ExecStartCmd execStart = mock(ExecStartCmd.class);
                when(execStart.exec(any())).thenAnswer(startInvocation -> {
                    @SuppressWarnings("unchecked")
                    ResultCallback<Frame> callback = startInvocation.getArgument(0);
                    if ("userdata-exec".equals(execId)) {
                        userDataStarted.countDown();
                        // test docker api frame
                        Frame frame = new Frame(StreamType.STDOUT, TEST_USER_DATA_OUTPUT.getBytes(StandardCharsets.UTF_8));
                        callback.onNext(frame);
                        finishUserData.await(2, TimeUnit.SECONDS);
                    }
                    else if (currentCommand.get() != null
                            && currentCommand.get().length > 0
                            && "curl".equals(currentCommand.get()[0])) {
                        callback.onNext(new Frame(StreamType.STDOUT,
                                "i-systemd".getBytes(StandardCharsets.UTF_8)));
                    }
                    callback.onComplete();
                    return callback;
                });
                return execStart;
            });

            InspectExecCmd inspectExec = mock(InspectExecCmd.class);
            InspectExecResponse inspectExecResponse = mock(InspectExecResponse.class);
            when(inspectExecResponse.getExitCodeLong()).thenReturn(0L);
            when(inspectExec.exec()).thenReturn(inspectExecResponse);
            when(dockerClient.inspectExecCmd(anyString())).thenReturn(inspectExec);

            CopyArchiveToContainerCmd copy = mock(CopyArchiveToContainerCmd.class, withSettings().defaultAnswer(RETURNS_SELF));
            when(dockerClient.copyArchiveToContainerCmd(TEST_CONTAINER_ID)).thenReturn(copy);
            when(copy.withTarInputStream(any(InputStream.class))).thenReturn(copy);
        }
    }
}
