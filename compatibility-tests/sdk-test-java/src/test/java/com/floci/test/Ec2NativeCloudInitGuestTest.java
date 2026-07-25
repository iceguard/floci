package com.floci.test;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeImagesRequest;
import software.amazon.awssdk.services.ec2.model.Filter;
import software.amazon.awssdk.services.ec2.model.IamInstanceProfileSpecification;
import software.amazon.awssdk.services.ec2.model.InstanceType;
import software.amazon.awssdk.services.ec2.model.RunInstancesRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfSystemProperty(named = "floci.native-cloud-init-it", matches = "true")
class Ec2NativeCloudInitGuestTest {

    private static final String STOCK_UBUNTU_IMAGE_NAME =
            "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*";
    private static final Duration GUEST_START_TIMEOUT = Duration.ofSeconds(60);
    private static final Duration CLOUD_INIT_TIMEOUT = Duration.ofSeconds(90);
    private static final int USER_DATA_TIMEOUT_SECONDS = Integer.getInteger(
            "floci.native-cloud-init.user-data-timeout-seconds", 900);

    @Test
    void nativeCloudInitLifecycleMatchesEc2GuestSemantics() throws Exception {
        try (AcmClient acm = TestFixtures.acmClient();
                Ec2Client ec2 = TestFixtures.ec2Client()) {
            proveSuccessAndReboot(acm, ec2);
            proveFailure(ec2);
            proveTimeout(ec2);
        }
    }

    private static void proveSuccessAndReboot(AcmClient acm, Ec2Client ec2) throws Exception {
        String userData = """
                #!/bin/sh
                set -eu
                count=0
                [ ! -f /var/lib/floci-cloud-init-count ] || count=$(cat /var/lib/floci-cloud-init-count)
                printf '%s\n' "$((count + 1))" > /var/lib/floci-cloud-init-count
                """;
        String instanceId = launch(ec2, userData);
        String container = containerName(instanceId);
        String certificateArn = null;
        try {
            waitForContainer(container, true, GUEST_START_TIMEOUT);
            certificateArn = acm.requestCertificate(request -> request.domainName("native-cloud-init.test"))
                    .certificateArn();
            String requestedCertificateArn = certificateArn;
            String certificateChain = acm.getCertificate(request -> request.certificateArn(requestedCertificateArn))
                    .certificateChain();
            CommandResult cloudInit = command(CLOUD_INIT_TIMEOUT,
                    "docker", "exec", container, "cloud-init", "status", "--wait", "--long");
            assertThat(cloudInit.exitCode()).isZero();
            assertThat(cloudInit.output()).contains("extended_status: done", "DataSourceEc2");
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "sha256sum", "/var/lib/cloud/instance/user-data.txt").output())
                    .startsWith(sha256(userData));
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "curl", "-fsS",
                    "http://169.254.169.254/2021-03-23/meta-data/instance-id").output().trim())
                    .isEqualTo(instanceId);
            assertMetadataRemainsAvailableAfterRepeatedRequests(container, instanceId);
            assertThat(command(Duration.ofSeconds(10), "docker", "exec", container, "env").output())
                    .doesNotContain("AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN=");
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "cat", "/var/lib/floci-cloud-init-count").output().trim())
                    .isEqualTo("1");
            String trustAnchor = "/usr/local/share/ca-certificates/floci-acm-trust-1.crt";
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "sha256sum", trustAnchor).output())
                    .startsWith(sha256(certificateChain.strip() + "\n"));
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "test", "-L",
                    "/etc/ssl/certs/floci-acm-trust-1.pem").exitCode())
                    .isZero();
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "openssl", "verify",
                    "-CApath", "/etc/ssl/certs", trustAnchor).output())
                    .contains(trustAnchor + ": OK");

            ec2.rebootInstances(request -> request.instanceIds(instanceId));
            waitUntil(() -> command(Duration.ofSeconds(10),
                            "docker", "exec", container, "curl", "-fsS",
                            "http://169.254.169.254/latest/meta-data/instance-id")
                            .output().trim().equals(instanceId),
                    CLOUD_INIT_TIMEOUT, "IMDS did not recover after reboot");
            waitUntil(() -> command(Duration.ofSeconds(10),
                            "docker", "exec", container, "cloud-init", "status", "--long")
                            .output().contains("extended_status: done"),
                    CLOUD_INIT_TIMEOUT, "cloud-init did not finish after reboot");
            assertThat(command(Duration.ofSeconds(10), "docker", "exec", container,
                    "cloud-init", "status", "--long").output())
                    .contains("extended_status: done", "DataSourceEc2");
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "cat", "/var/lib/floci-cloud-init-count").output().trim())
                    .isEqualTo("1");
        }
        finally {
            try {
                terminate(ec2, instanceId, container);
            }
            finally {
                if (certificateArn != null) {
                    String requestedCertificateArn = certificateArn;
                    acm.deleteCertificate(request -> request.certificateArn(requestedCertificateArn));
                }
            }
        }
    }

    private static void assertMetadataRemainsAvailableAfterRepeatedRequests(String container, String instanceId)
            throws Exception {
        for (int request = 0; request < 80; request++) {
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "curl", "-fsS",
                    "http://169.254.169.254/latest/meta-data/instance-id").output().trim())
                    .as("IMDS request %s", request + 1)
                    .isEqualTo(instanceId);
        }
    }

    private static void proveFailure(Ec2Client ec2) throws Exception {
        String instanceId = launch(ec2, "#!/bin/sh\nset -eu\nexit 23\n");
        String container = containerName(instanceId);
        try {
            waitForContainer(container, true, GUEST_START_TIMEOUT);
            CommandResult cloudInit = command(CLOUD_INIT_TIMEOUT,
                    "docker", "exec", container, "cloud-init", "status", "--wait", "--long");
            assertThat(cloudInit.exitCode()).isNotZero();
            assertThat(cloudInit.output()).contains("extended_status: error", "DataSourceEc2");
        }
        finally {
            terminate(ec2, instanceId, container);
        }
    }

    private static void proveTimeout(Ec2Client ec2) throws Exception {
        int sleepSeconds = USER_DATA_TIMEOUT_SECONDS + 30;
        String instanceId = launch(ec2, "#!/bin/sh\nset -eu\nsleep " + sleepSeconds
                + "\nprintf completed > /var/lib/should-not-exist\n");
        String container = containerName(instanceId);
        try {
            waitForContainer(container, true, GUEST_START_TIMEOUT);
            waitUntil(() -> command(Duration.ofSeconds(10),
                            "docker", "exec", container, "pgrep", "-f", "^sleep " + sleepSeconds + "$").exitCode() == 0,
                    GUEST_START_TIMEOUT, "the timeout fixture never started");
            waitUntil(() -> command(Duration.ofSeconds(10),
                            "docker", "exec", container, "pgrep", "-f", "^sleep " + sleepSeconds + "$").exitCode() != 0,
                    Duration.ofSeconds(USER_DATA_TIMEOUT_SECONDS + 30L),
                    "the timed-out user-data process was not terminated");
            CommandResult finalUnit = command(Duration.ofSeconds(10),
                    "docker", "exec", container, "systemctl", "is-active", "cloud-final.service");
            assertThat(finalUnit.exitCode()).isNotZero();
            assertThat(finalUnit.output().trim()).isNotEqualTo("active");
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "pgrep", "-f", "^sleep " + sleepSeconds + "$").exitCode()).isNotZero();
            assertThat(command(Duration.ofSeconds(10),
                    "docker", "exec", container, "test", "-e", "/var/lib/should-not-exist").exitCode())
                    .isNotZero();
        }
        finally {
            terminate(ec2, instanceId, container);
        }
    }

    private static String launch(Ec2Client ec2, String userData) {
        return ec2.runInstances(RunInstancesRequest.builder()
                        .imageId(stockUbuntuImageId(ec2))
                        .instanceType(InstanceType.fromValue("t4g.small"))
                        .iamInstanceProfile(IamInstanceProfileSpecification.builder()
                                .arn("arn:aws:iam::000000000000:instance-profile/native-cloud-init-test")
                                .build())
                        .minCount(1)
                        .maxCount(1)
                        .userData(Base64.getEncoder().encodeToString(userData.getBytes(StandardCharsets.UTF_8)))
                        .build())
                .instances()
                .get(0)
                .instanceId();
    }

    private static String stockUbuntuImageId(Ec2Client ec2) {
        return ec2.describeImages(DescribeImagesRequest.builder()
                        .owners("099720109477")
                        .filters(
                                Filter.builder().name("name").values(STOCK_UBUNTU_IMAGE_NAME).build(),
                                Filter.builder().name("architecture").values("arm64").build(),
                                Filter.builder().name("state").values("available").build())
                        .build())
                .images()
                .getFirst()
                .imageId();
    }

    private static void terminate(Ec2Client ec2, String instanceId, String container) throws Exception {
        ec2.terminateInstances(request -> request.instanceIds(instanceId));
        waitForContainer(container, false, GUEST_START_TIMEOUT);
    }

    private static String containerName(String instanceId) {
        String prefix = System.getProperty("floci.native-cloud-init.container-prefix", "floci-ec2-");
        return prefix + instanceId;
    }

    private static void waitForContainer(String container, boolean expected, Duration timeout) throws Exception {
        waitUntil(() -> (command(Duration.ofSeconds(10), "docker", "inspect", container).exitCode() == 0) == expected,
                timeout, "container presence did not become " + expected + ": " + container);
    }

    private static void waitUntil(CheckedBooleanSupplier condition, Duration timeout, String message) throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(250);
        }
        assertThat(condition.getAsBoolean()).as(message).isTrue();
    }

    private static CommandResult command(Duration timeout, String... command) throws Exception {
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();
        if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            process.destroyForcibly();
            throw new IllegalStateException("Command timed out: " + String.join(" ", command));
        }
        return new CommandResult(
                process.exitValue(),
                new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
    }

    private static String sha256(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    @FunctionalInterface
    private interface CheckedBooleanSupplier {
        boolean getAsBoolean() throws Exception;
    }

    private record CommandResult(int exitCode, String output) {}
}
