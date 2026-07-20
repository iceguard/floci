package io.github.hectorvent.floci.tools.ami;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AmiImageToolTest {
    @TempDir
    Path tempDir;

    @Test
    void metadataDrivesGenerationAndCatalogUpdate() throws Exception {
        Path release = Files.createDirectories(tempDir.resolve("release-20260615"));
        Path rootfs = release.resolve("ubuntu-root.tar.xz");
        Path manifest = release.resolve("ubuntu.manifest");
        Files.writeString(rootfs, "rootfs", StandardCharsets.UTF_8);
        Files.writeString(manifest, "systemd\t1\ncloud-init\t1\n", StandardCharsets.UTF_8);
        Path metadata = tempDir.resolve("image-build-metadata.yaml");
        Files.writeString(metadata, """
                releaseId: test-release
                images:
                  - id: ubuntu-24.04-arm64
                    catalogImageId: ami-ubuntu2404-arm64
                    catalogAliases: [ami-ubuntu2404, ami-ubuntu2404-cloud-arm64, ami-ubuntu2404-cloud]
                    family: ubuntu
                    version: "24.04"
                    architecture: arm64
                    aws:
                      region: us-east-1
                      ownerId: "099720109477"
                      imageId: ami-source
                      name: ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-20260615
                      creationDate: "2026-06-15T00:00:00.000Z"
                      virtualizationType: hvm
                      rootDeviceType: ebs
                    canonical:
                      releaseSerial: "20260615"
                      baseUrl: %s
                      rootfs: %s
                      rootfsSha256: %s
                      manifest: %s
                      manifestSha256: %s
                    docker:
                      image: floci/ami-ubuntu:24.04-arm64-sha256-%s
                    guest:
                      runtime: systemd
                      cloudInit: true
                      cloudInitVersion: "1"
                      smokePackages: [systemd, cloud-init]
                """.formatted(release.toUri(), rootfs.getFileName(), sha256(rootfs), manifest.getFileName(),
                sha256(manifest), sha256(rootfs)));

        AmiImageTool.Metadata loaded = AmiImageTool.loadMetadata(metadata);
        AmiImageTool.ImageSpec image = loaded.images.getFirst();
        Path context = AmiImageTool.generate(image, tempDir.resolve("out"), true);

        String dockerfile = Files.readString(context.resolve("Dockerfile"));
        assertTrue(dockerfile.contains("FROM scratch"));
        assertTrue(dockerfile.contains("org.opencontainers.image.source=\"" + release.toUri() + "ubuntu-root.tar.xz\""));
        assertTrue(dockerfile.contains("org.opencontainers.image.version=\"24.04-20260615\""));
        assertTrue(dockerfile.contains("org.opencontainers.image.created=\"2026-06-15T00:00:00.000Z\""));
        assertFalse(dockerfile.contains("org.opencontainers.image.revision"));
        assertTrue(dockerfile.contains("io.floci.ami.canonical.release=\"20260615\""));
        assertTrue(dockerfile.contains("io.floci.ami.rootfs.sha256=\"" + sha256(rootfs) + "\""));
        assertTrue(dockerfile.contains("io.floci.ami.manifest.sha256=\"" + sha256(manifest) + "\""));
        assertTrue(dockerfile.contains("io.floci.ami.cloud-init.version=\"1\""));
        assertTrue(dockerfile.contains("ADD ubuntu-root.tar.xz /"));
        assertTrue(dockerfile.contains("useradd --uid 1000 --gid ubuntu"));
        assertTrue(dockerfile.contains("systemd-networkd-wait-online.service.d/floci.conf"));
        assertTrue(Files.readString(context.resolve("systemd-networkd-wait-online-floci.conf")).contains("ExecStart=/bin/true"));
        assertTrue(Files.readString(context.resolve("provenance.yaml")).contains("manifestSha256"));
        assertEquals(List.of("docker", "build", "--platform", "linux/arm64", "-t", image.docker.image,
                context.toString()), AmiImageTool.buildCommand(image, context));
        assertTrue(AmiImageTool.smokeCommand(image).contains("linux/arm64"));
        assertTrue(AmiImageTool.smokeCommand(image).getLast().contains("cloud-init --version"));

        Path catalog = tempDir.resolve("image-catalog.yaml");
        Files.writeString(catalog, """
                defaultDockerImage: public.ecr.aws/amazonlinux/amazonlinux:2023
                images:
                  - imageId: ami-existing
                    dockerImage: public.ecr.aws/docker/library/ubuntu:24.04
                    name: existing
                    description: existing
                    architecture: arm64
                    creationDate: "2026-01-01T00:00:00.000Z"
                  - imageId: ami-ubuntu2404-arm64
                    dockerImage: old-stock
                  - imageId: ami-ubuntu2404-cloud-arm64
                    dockerImage: old-cloud
                """);
        Path output = tempDir.resolve("custom-output");
        AmiImageTool.updateCatalog(image, catalog, output, true);
        String catalogText = Files.readString(catalog);
        assertTrue(catalogText.contains("ami-existing"));
        assertEquals(1, occurrences(catalogText, "imageId: \"ami-ubuntu2404-arm64\""));
        assertTrue(catalogText.contains("ami-ubuntu2404-cloud-arm64"));
        assertTrue(catalogText.contains("guestRuntime: \"systemd\""));
        assertTrue(catalogText.contains("cloudInit: true"));
        assertTrue(catalogText.contains("custom-output/ubuntu-24.04-arm64/provenance.yaml"));
    }

    @Test
    void metadataRejectsMutableReleaseAndPartialContentAddress() throws Exception {
        Path metadata = tempDir.resolve("mutable.yaml");
        String digest = "a".repeat(64);
        Files.writeString(metadata, validMetadata("https://cloud-images.ubuntu.com/releases/noble/release",
                digest, "floci/ami-ubuntu:24.04-arm64-sha256-" + digest.substring(0, 12)));

        IllegalArgumentException mutable = assertThrows(
                IllegalArgumentException.class, () -> AmiImageTool.loadMetadata(metadata));
        assertTrue(mutable.getMessage().contains("immutable release path /release-20260615"));

        Files.writeString(metadata, validMetadata(
                "https://cloud-images.ubuntu.com/releases/noble/release-20260615",
                digest, "floci/ami-ubuntu:24.04-arm64-sha256-" + digest.substring(0, 12)));
        IllegalArgumentException partial = assertThrows(
                IllegalArgumentException.class, () -> AmiImageTool.loadMetadata(metadata));
        assertTrue(partial.getMessage().contains("full rootfs content address"));
    }

    @Test
    void metadataRejectsDockerLibraryUbuntuAsSource() throws Exception {
        Path badRootfsMetadata = tempDir.resolve("bad-rootfs.yaml");
        Files.writeString(badRootfsMetadata, """
                releaseId: bad
                images:
                  - id: bad
                    catalogImageId: ami-bad
                    family: ubuntu
                    version: "24.04"
                    architecture: arm64
                    aws:
                      region: us-east-1
                      ownerId: "099720109477"
                      imageId: ami-bad-source
                      name: bad
                      creationDate: "2026-05-15T00:00:00.000Z"
                      virtualizationType: hvm
                      rootDeviceType: ebs
                    canonical:
                      releaseSerial: "20260615"
                      baseUrl: https://example.com/release-20260615
                      rootfs: ubuntu:24.04
                      rootfsSha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                      manifest: manifest
                      manifestSha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
                    docker:
                      image: floci/ami-ubuntu:24.04-arm64-sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                    guest: { runtime: systemd, cloudInit: true, cloudInitVersion: "1" }
                """);

        assertThrows(IllegalArgumentException.class, () -> AmiImageTool.loadMetadata(badRootfsMetadata));

        Path badDockerMetadata = tempDir.resolve("bad-docker.yaml");
        Files.writeString(badDockerMetadata, """
                releaseId: bad
                images:
                  - id: bad
                    catalogImageId: ami-bad
                    family: ubuntu
                    version: "24.04"
                    architecture: arm64
                    aws:
                      region: us-east-1
                      ownerId: "099720109477"
                      imageId: ami-bad-source
                      name: bad
                      creationDate: "2026-05-15T00:00:00.000Z"
                      virtualizationType: hvm
                      rootDeviceType: ebs
                    canonical:
                      releaseSerial: "20260615"
                      baseUrl: https://example.com/release-20260615
                      rootfs: ubuntu-root.tar.xz
                      rootfsSha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                      manifest: manifest
                      manifestSha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
                    docker: { image: public.ecr.aws/docker/library/ubuntu:24.04 }
                    guest: { runtime: systemd, cloudInit: true, cloudInitVersion: "1" }
                """);

        assertThrows(IllegalArgumentException.class, () -> AmiImageTool.loadMetadata(badDockerMetadata));
    }

    @Test
    void toolTreeDoesNotContainShellScripts() throws Exception {
        Path tools = Path.of("src/main/java/io/github/hectorvent/floci/tools/ami");
        if (Files.isDirectory(tools)) {
            try (var stream = Files.walk(tools)) {
                assertFalse(stream.anyMatch(path -> path.getFileName().toString().endsWith(".sh")));
            }
        }
    }

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(Files.readAllBytes(path));
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String validMetadata(String baseUrl, String digest, String dockerImage) {
        return """
                releaseId: test
                images:
                  - id: ubuntu-24.04-arm64
                    catalogImageId: ami-ubuntu2404-arm64
                    family: ubuntu
                    version: "24.04"
                    architecture: arm64
                    aws:
                      region: us-east-1
                      ownerId: "099720109477"
                      imageId: ami-ubuntu2404-arm64
                      name: ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-20260615
                      creationDate: "2026-06-15T00:00:00.000Z"
                      virtualizationType: hvm
                      rootDeviceType: ebs
                    canonical:
                      releaseSerial: "20260615"
                      baseUrl: %s
                      rootfs: root.tar.xz
                      rootfsSha256: %s
                      manifest: image.manifest
                      manifestSha256: %s
                    docker:
                      image: %s
                    guest:
                      runtime: systemd
                      cloudInit: true
                      cloudInitVersion: "1"
                """.formatted(baseUrl, digest, digest, dockerImage);
    }

    private static int occurrences(String value, String needle) {
        return (value.length() - value.replace(needle, "").length()) / needle.length();
    }
}
