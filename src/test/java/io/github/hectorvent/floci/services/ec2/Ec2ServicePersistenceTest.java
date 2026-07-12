package io.github.hectorvent.floci.services.ec2;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.storage.PersistentStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.services.ec2.model.Address;
import io.github.hectorvent.floci.services.ec2.model.BlockDeviceMapping;
import io.github.hectorvent.floci.services.ec2.model.EbsBlockDevice;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.InstanceBootstrapResult;
import io.github.hectorvent.floci.services.ec2.model.InternetGateway;
import io.github.hectorvent.floci.services.ec2.model.Image;
import io.github.hectorvent.floci.services.ec2.model.NetworkAcl;
import io.github.hectorvent.floci.services.ec2.model.KeyPair;
import io.github.hectorvent.floci.services.ec2.model.LaunchTemplate;
import io.github.hectorvent.floci.services.ec2.model.LaunchTemplateData;
import io.github.hectorvent.floci.services.ec2.model.LaunchSpecification;
import io.github.hectorvent.floci.services.ec2.model.NatGateway;
import io.github.hectorvent.floci.services.ec2.model.RouteTable;
import io.github.hectorvent.floci.services.ec2.model.SecurityGroup;
import io.github.hectorvent.floci.services.ec2.model.SecurityGroupRule;
import io.github.hectorvent.floci.services.ec2.model.Snapshot;
import io.github.hectorvent.floci.services.ec2.model.Subnet;
import io.github.hectorvent.floci.services.ec2.model.Tag;
import io.github.hectorvent.floci.services.ec2.model.Volume;
import io.github.hectorvent.floci.services.ec2.model.Vpc;
import io.github.hectorvent.floci.services.ec2.model.VpcEndpoint;
import io.github.hectorvent.floci.services.ec2.model.SpotInstanceRequest;
import io.github.hectorvent.floci.services.ec2.portforward.Ec2PortForwardManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Regression test for issue #1297 (persistent-restart case). EC2 networking and instance metadata
 * must be persisted via StorageFactory so that the VPC/subnet ids CloudFormation exports survive a
 * Floci restart. Before the fix Ec2Service used plain in-memory maps, so after a restart the
 * persisted CloudFormation exports/stack referenced VPC/subnet ids that EC2 had lost
 * (describe-subnets returned [] and ELBv2 failed with SubnetNotFound).
 *
 * <p>This builds an Ec2Service over PersistentStorage in a temp dir, creates a VPC/subnet, then
 * builds a SECOND Ec2Service over the SAME files (simulating a process restart) and asserts the
 * resources are still visible.
 */
class Ec2ServicePersistenceTest {

    private static final String REGION = "us-east-1";

    @Test
    void redactedBootstrapResultSurvivesRestart(@TempDir Path dir) {
        InstanceBootstrapResult result = new InstanceBootstrapResult();
        result.setStatus("FAILED");
        result.setStartedAt(Instant.parse("2026-07-12T12:00:00Z"));
        result.setCompletedAt(Instant.parse("2026-07-12T12:00:05Z"));
        result.setExitCode(1);
        result.setMessage("Cloud-init failed");
        Instance instance = new Instance();
        instance.setInstanceId("i-bootstrap-result-persistence");
        instance.setBootstrapResult(result);

        StorageBackend<String, Instance> first = load(
                dir, "ec2-instances.json", new TypeReference<Map<String, Instance>>() {});
        first.put(REGION + "::" + instance.getInstanceId(), instance);

        Instance restored = load(dir, "ec2-instances.json", new TypeReference<Map<String, Instance>>() {})
                .get(REGION + "::" + instance.getInstanceId())
                .orElseThrow();
        assertEquals("FAILED", restored.getBootstrapResult().getStatus());
        assertEquals(1, restored.getBootstrapResult().getExitCode());
        assertEquals("Cloud-init failed", restored.getBootstrapResult().getMessage());
    }

    @Test
    void emptyNetworkDiscoverySurvivesRestart(@TempDir Path dir) {
        Ec2Service first = newService(dir);
        assertTrue(first.describeVpcPeeringConnectionIds(REGION, List.of(), Map.of()).isEmpty());
        assertTrue(first.describeTransitGatewayVpcAttachmentIds(REGION, List.of(), Map.of()).isEmpty());
        assertTrue(first.describeVpnGatewayIds(REGION, List.of(), Map.of()).isEmpty());
        assertTrue(first.describeEgressOnlyInternetGatewayIds(REGION, List.of(), Map.of()).isEmpty());

        Ec2Service restarted = newService(dir);
        assertTrue(restarted.describeVpcPeeringConnectionIds(
                REGION, List.of(), Map.of("status-code", List.of("active"))).isEmpty());
        assertTrue(restarted.describeTransitGatewayVpcAttachmentIds(
                REGION, List.of(), Map.of("state", List.of("available"))).isEmpty());
        assertTrue(restarted.describeVpnGatewayIds(
                REGION, List.of(), Map.of("attachment.vpc-id", List.of("vpc-0123456789abcdef0"))).isEmpty());
        assertTrue(restarted.describeEgressOnlyInternetGatewayIds(
                REGION, List.of(), Map.of("tag:Owner", List.of("TeamA"))).isEmpty());
    }

    @Test
    void exactUserDataBytesSurviveRestart(@TempDir Path dir) {
        byte[] bytes = new byte[]{0x1f, (byte) 0x8b, 0x00, (byte) 0xff};
        String encoded = Base64.getEncoder().encodeToString(bytes);

        Instance instance = new Instance();
        instance.setInstanceId("i-user-data-persistence");
        instance.setEncodedUserData(encoded);
        StorageBackend<String, Instance> firstInstances = load(
                dir, "ec2-instances.json", new TypeReference<Map<String, Instance>>() {});
        firstInstances.put(REGION + "::" + instance.getInstanceId(), instance);

        LaunchTemplateData version = new LaunchTemplateData();
        version.setEncodedUserData(encoded);
        LaunchTemplate launchTemplate = new LaunchTemplate();
        launchTemplate.setLaunchTemplateId("lt-user-data-persistence");
        launchTemplate.setEncodedUserData(encoded);
        launchTemplate.getVersions().put("1", version);
        StorageBackend<String, LaunchTemplate> firstTemplates = load(
                dir, "ec2-launch-templates.json", new TypeReference<Map<String, LaunchTemplate>>() {});
        firstTemplates.put(REGION + "::" + launchTemplate.getLaunchTemplateId(), launchTemplate);

        LaunchSpecification specification = new LaunchSpecification();
        specification.setEncodedUserData(encoded);
        SpotInstanceRequest spotRequest = new SpotInstanceRequest();
        spotRequest.setSpotInstanceRequestId("sir-user-data-persistence");
        spotRequest.setLaunchSpecification(specification);
        StorageBackend<String, SpotInstanceRequest> firstSpotRequests = load(
                dir, "ec2-spot-instance-requests.json",
                new TypeReference<Map<String, SpotInstanceRequest>>() {});
        firstSpotRequests.put(REGION + "::" + spotRequest.getSpotInstanceRequestId(), spotRequest);

        StorageBackend<String, Instance> restartedInstances = load(
                dir, "ec2-instances.json", new TypeReference<Map<String, Instance>>() {});
        assertEquals(encoded, restartedInstances.get(REGION + "::" + instance.getInstanceId())
                .orElseThrow()
                .getEncodedUserData());
        StorageBackend<String, LaunchTemplate> restartedTemplates = load(
                dir, "ec2-launch-templates.json", new TypeReference<Map<String, LaunchTemplate>>() {});
        LaunchTemplate restartedTemplate = restartedTemplates.get(
                REGION + "::" + launchTemplate.getLaunchTemplateId()).orElseThrow();
        assertEquals(encoded, restartedTemplate.getEncodedUserData());
        assertEquals(encoded, restartedTemplate.getVersions().get("1").getEncodedUserData());
        StorageBackend<String, SpotInstanceRequest> restartedSpotRequests = load(
                dir, "ec2-spot-instance-requests.json",
                new TypeReference<Map<String, SpotInstanceRequest>>() {});
        assertEquals(encoded, restartedSpotRequests.get(
                        REGION + "::" + spotRequest.getSpotInstanceRequestId()).orElseThrow()
                .getLaunchSpecification().getEncodedUserData());
    }

    @Test
    void legacyTextUserDataMigratesAcrossAllPersistedModels(@TempDir Path dir) throws IOException {
        String legacyText = "#!/bin/sh\necho legacy\n";
        String encoded = Base64.getEncoder().encodeToString(legacyText.getBytes());

        Files.writeString(dir.resolve("ec2-instances.json"), """
                {
                  "us-east-1::i-legacy": {
                    "instanceId": "i-legacy",
                    "userData": "#!/bin/sh\\necho legacy\\n"
                  }
                }
                """);
        Files.writeString(dir.resolve("ec2-launch-templates.json"), """
                {
                  "us-east-1::lt-legacy": {
                    "launchTemplateId": "lt-legacy",
                    "userData": "#!/bin/sh\\necho legacy\\n",
                    "versions": {
                      "1": {
                        "userData": "#!/bin/sh\\necho legacy\\n"
                      }
                    }
                  }
                }
                """);
        Files.writeString(dir.resolve("ec2-spot-instance-requests.json"), """
                {
                  "us-east-1::sir-legacy": {
                    "spotInstanceRequestId": "sir-legacy",
                    "launchSpecification": {
                      "userData": "#!/bin/sh\\necho legacy\\n"
                    }
                  }
                }
                """);

        StorageBackend<String, Instance> instances = load(
                dir, "ec2-instances.json", new TypeReference<Map<String, Instance>>() {});
        assertEquals(encoded, instances.get("us-east-1::i-legacy").orElseThrow().getEncodedUserData());

        StorageBackend<String, LaunchTemplate> templates = load(
                dir, "ec2-launch-templates.json", new TypeReference<Map<String, LaunchTemplate>>() {});
        LaunchTemplate template = templates.get("us-east-1::lt-legacy").orElseThrow();
        assertEquals(encoded, template.getEncodedUserData());
        assertEquals(encoded, template.getVersions().get("1").getEncodedUserData());

        StorageBackend<String, SpotInstanceRequest> spotRequests = load(
                dir, "ec2-spot-instance-requests.json",
                new TypeReference<Map<String, SpotInstanceRequest>>() {});
        assertEquals(encoded, spotRequests.get("us-east-1::sir-legacy").orElseThrow()
                .getLaunchSpecification().getEncodedUserData());
    }

    @Test
    void canonicalEncodedUserDataWinsOverLegacyTextInEitherPropertyOrder(@TempDir Path dir)
            throws IOException {
        String canonical = Base64.getEncoder().encodeToString(new byte[]{0x00, (byte) 0xff});

        Files.writeString(dir.resolve("ec2-instances.json"), """
                {
                  "us-east-1::i-first": {
                    "instanceId": "i-first",
                    "encodedUserData": "%s",
                    "userData": "legacy"
                  },
                  "us-east-1::i-last": {
                    "instanceId": "i-last",
                    "userData": "legacy",
                    "encodedUserData": "%s"
                  }
                }
                """.formatted(canonical, canonical));

        StorageBackend<String, Instance> instances = load(
                dir, "ec2-instances.json", new TypeReference<Map<String, Instance>>() {});
        assertEquals(canonical, instances.get("us-east-1::i-first").orElseThrow().getEncodedUserData());
        assertEquals(canonical, instances.get("us-east-1::i-last").orElseThrow().getEncodedUserData());
    }

    @Test
    void vpcAndSubnetSurviveRestart(@TempDir Path dir) {
        Ec2Service first = newService(dir);
        Vpc vpc = first.createVpc(REGION, "10.0.0.0/16", false);
        Subnet subnet = first.createSubnet(REGION, vpc.getVpcId(), "10.0.1.0/24", REGION + "a");

        // A fresh service over the same persistent files = a restart with the same data dir.
        Ec2Service restarted = newService(dir);

        List<Vpc> vpcs = restarted.describeVpcs(REGION, List.of(vpc.getVpcId()), Map.of());
        assertEquals(1, vpcs.size(), "VPC must survive restart");
        assertEquals("10.0.0.0/16", vpcs.get(0).getCidrBlock());

        List<Subnet> subnets = restarted.describeSubnets(REGION, List.of(subnet.getSubnetId()), Map.of());
        assertEquals(1, subnets.size(), "Subnet must survive restart");
        assertEquals(vpc.getVpcId(), subnets.get(0).getVpcId());
        assertEquals("10.0.1.0/24", subnets.get(0).getCidrBlock());
    }

    @Test
    void deletedVpcDefaultResourcesRemainAbsentAfterRestart(@TempDir Path dir) {
        Ec2Service first = newService(dir);
        Vpc vpc = first.createVpc(REGION, "10.77.0.0/16", false);
        SecurityGroup defaultGroup = first.describeSecurityGroups(REGION, List.of(), List.of(), Map.of()).stream()
                .filter(group -> vpc.getVpcId().equals(group.getVpcId()) && "default".equals(group.getGroupName()))
                .findFirst().orElseThrow();
        String mainRouteTableId = first.describeRouteTables(REGION, List.of(), Map.of()).stream()
                .filter(table -> vpc.getVpcId().equals(table.getVpcId()))
                .filter(table -> table.getAssociations().stream().anyMatch(association -> association.isMain()))
                .findFirst().orElseThrow().getRouteTableId();
        String defaultNetworkAclId = first.describeNetworkAcls(REGION, List.of(), Map.of()).stream()
                .filter(acl -> vpc.getVpcId().equals(acl.getVpcId()) && acl.isDefault())
                .findFirst().orElseThrow().getNetworkAclId();

        first.deleteVpc(REGION, vpc.getVpcId());
        Ec2Service restarted = newService(dir);

        assertTrue(restarted.describeVpcs(REGION, List.of(), Map.of()).stream()
                .noneMatch(candidate -> vpc.getVpcId().equals(candidate.getVpcId())));
        assertTrue(restarted.describeSecurityGroups(
                REGION, List.of(defaultGroup.getGroupId()), List.of(), Map.of()).isEmpty());
        assertTrue(restarted.describeSecurityGroupRules(
                REGION, List.of(defaultGroup.getGroupId()), List.of()).isEmpty());
        assertTrue(restarted.describeRouteTables(REGION, List.of(mainRouteTableId), Map.of()).isEmpty());
        assertTrue(restarted.describeNetworkAcls(REGION, List.of(defaultNetworkAclId), Map.of()).isEmpty());
    }

    @Test
    void registeredImageAndSnapshotSurviveRestart(@TempDir Path dir) {
        Ec2Service first = newService(dir);
        Image image = first.registerImage(REGION, "persisted-image", "persisted image", "x86_64",
                "/dev/sda1", List.of(blockDeviceMapping("snap-persisted", 12)));

        Ec2Service restarted = newService(dir);

        List<Image> images = restarted.describeImages(REGION, List.of(image.getImageId()), List.of(), Map.of());
        assertEquals(1, images.size(), "registered image must survive restart");
        assertEquals("persisted-image", images.getFirst().getName());
        assertEquals("snap-persisted",
                images.getFirst().getBlockDeviceMappings().getFirst().getEbs().getSnapshotId());

        List<Snapshot> snapshots = restarted.describeSnapshots(REGION, List.of("snap-persisted"), List.of(), Map.of());
        assertEquals(1, snapshots.size(), "linked snapshot must survive restart");
        assertEquals(12, snapshots.getFirst().getVolumeSize());
    }

    private BlockDeviceMapping blockDeviceMapping(String snapshotId, int volumeSize) {
        EbsBlockDevice ebs = new EbsBlockDevice();
        ebs.setSnapshotId(snapshotId);
        ebs.setVolumeSize(volumeSize);
        BlockDeviceMapping mapping = new BlockDeviceMapping();
        mapping.setDeviceName("/dev/sda1");
        mapping.setEbs(ebs);
        return mapping;
    }

    private Ec2Service newService(Path dir) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        when(config.defaultAccountId()).thenReturn("000000000000");
        Ec2ImageCatalog imageCatalog = new Ec2ImageCatalog();
        return new Ec2Service(config, null, mock(Ec2PortForwardManager.class),
                new AmiImageResolver(imageCatalog), imageCatalog,
                new Ec2InstanceTypeCatalog(),
                load(dir, "ec2-vpcs.json", new TypeReference<Map<String, Vpc>>() {}),
                load(dir, "ec2-subnets.json", new TypeReference<Map<String, Subnet>>() {}),
                load(dir, "ec2-security-groups.json", new TypeReference<Map<String, SecurityGroup>>() {}),
                load(dir, "ec2-security-group-rules.json", new TypeReference<Map<String, SecurityGroupRule>>() {}),
                load(dir, "ec2-internet-gateways.json", new TypeReference<Map<String, InternetGateway>>() {}),
                load(dir, "ec2-route-tables.json", new TypeReference<Map<String, RouteTable>>() {}),
                load(dir, "ec2-key-pairs.json", new TypeReference<Map<String, KeyPair>>() {}),
                load(dir, "ec2-addresses.json", new TypeReference<Map<String, Address>>() {}),
                load(dir, "ec2-instances.json", new TypeReference<Map<String, Instance>>() {}),
                load(dir, "ec2-volumes.json", new TypeReference<Map<String, Volume>>() {}),
                load(dir, "ec2-registered-images.json", new TypeReference<Map<String, Image>>() {}),
                load(dir, "ec2-snapshots.json", new TypeReference<Map<String, Snapshot>>() {}),
                load(dir, "ec2-launch-templates.json", new TypeReference<Map<String, LaunchTemplate>>() {}),
                load(dir, "ec2-vpc-endpoints.json", new TypeReference<Map<String, VpcEndpoint>>() {}),
                load(dir, "ec2-nat-gateways.json", new TypeReference<Map<String, NatGateway>>() {}),
                load(dir, "ec2-spot-instance-requests.json", new TypeReference<Map<String, SpotInstanceRequest>>() {}),
                load(dir, "ec2-network-acls.json", new TypeReference<Map<String, NetworkAcl>>() {}),
                load(dir, "ec2-tags.json", new TypeReference<Map<String, List<Tag>>>() {}));
    }

    private <V> StorageBackend<String, V> load(Path dir, String file, TypeReference<Map<String, V>> type) {
        PersistentStorage<String, V> backend = new PersistentStorage<>(dir.resolve(file), type);
        backend.load();
        return backend;
    }
}
