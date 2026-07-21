package io.github.hectorvent.floci.services.rds;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.PersistentStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.model.Subnet;
import io.github.hectorvent.floci.services.rds.container.RdsContainerManager;
import io.github.hectorvent.floci.services.rds.model.DbCluster;
import io.github.hectorvent.floci.services.rds.model.DbClusterParameterGroup;
import io.github.hectorvent.floci.services.rds.model.DbInstance;
import io.github.hectorvent.floci.services.rds.model.DbParameterGroup;
import io.github.hectorvent.floci.services.rds.model.DbSubnetGroup;
import io.github.hectorvent.floci.services.rds.proxy.RdsProxyManager;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.services.secretsmanager.model.Secret;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RdsServicePersistenceTest {

    @Test
    void subnetAndParameterGroupArnsAndCreationTagsSurviveRestart(@TempDir Path dir) {
        RdsService first = newService(dir);
        DbSubnetGroup subnetGroup = first.createDbSubnetGroup(
                "application-subnets",
                "application subnets",
                List.of("subnet-a", "subnet-b"),
                "us-west-2",
                Map.of("normal", "network", "explicit-empty", "", "omitted", ""));
        DbParameterGroup parameterGroup = first.createDbParameterGroup(
                "application-postgres",
                "postgres18",
                "application parameters",
                "us-west-2",
                Map.of("normal", "database", "explicit-empty", "", "omitted", ""));
        first.addTagsToResource(
                subnetGroup.getDbSubnetGroupArn(),
                Map.of("added-normal", "network-added", "added-empty", ""));
        first.addTagsToResource(
                parameterGroup.getDbParameterGroupArn(),
                Map.of("added-normal", "database-added", "added-empty", ""));

        RdsService restarted = newService(dir);

        assertEquals(
                "arn:aws:rds:us-west-2:123456789012:subgrp:application-subnets",
                subnetGroup.getDbSubnetGroupArn());
        assertEquals(
                "arn:aws:rds:us-west-2:123456789012:pg:application-postgres",
                parameterGroup.getDbParameterGroupArn());
        assertEquals(
                Map.of(
                        "normal", "network",
                        "explicit-empty", "",
                        "omitted", "",
                        "added-normal", "network-added",
                        "added-empty", ""),
                restarted.listTagsForResource(subnetGroup.getDbSubnetGroupArn()));
        assertEquals(
                Map.of(
                        "normal", "database",
                        "explicit-empty", "",
                        "omitted", "",
                        "added-normal", "database-added",
                        "added-empty", ""),
                restarted.listTagsForResource(parameterGroup.getDbParameterGroupArn()));
    }

    @Test
    void persistedPreArnParameterGroupIsUpgradedOnRead(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("rds-parameter-groups.json"), """
                {
                  "legacy-postgres": {
                    "dbParameterGroupName": "legacy-postgres",
                    "dbParameterGroupFamily": "postgres16",
                    "description": "created before ARN persistence",
                    "parameters": {},
                    "tags": {"owner": "legacy"}
                  }
                }
                """);

        RdsService service = newService(dir);
        DbParameterGroup group = service.getDbParameterGroup("legacy-postgres", "us-east-1");

        assertEquals("arn:aws:rds:us-east-1:123456789012:pg:legacy-postgres",
                group.getDbParameterGroupArn());
        assertEquals(Map.of("owner", "legacy"),
                service.listTagsForResource(group.getDbParameterGroupArn()));

        RdsService restarted = newService(dir);
        assertEquals(group.getDbParameterGroupArn(),
                restarted.getDbParameterGroup("legacy-postgres", "us-east-1").getDbParameterGroupArn());
        assertEquals(Map.of("owner", "legacy"),
                restarted.listTagsForResource(group.getDbParameterGroupArn()));
    }

    @Test
    void autoMinorVersionUpgradeValuesSurviveRestart(@TempDir Path dir) {
        RdsService first = newService(dir);
        DbInstance disabled = first.createDbInstance(
                "disabled", "postgres", "16.3", "admin", "password", "app",
                "db.t3.micro", 20, false, null, null, null, null, false,
                false, null, Map.of(), List.of(), "us-east-1", false);
        DbInstance enabled = first.createDbInstance(
                "enabled", "postgres", "16.3", "admin", "password", "app",
                "db.t3.micro", 20, false, null, null, null, null, false,
                false, null, Map.of(), List.of(), "us-east-1", true);

        RdsService restarted = newService(dir);

        assertEquals(false, disabled.isAutoMinorVersionUpgrade());
        assertEquals(true, enabled.isAutoMinorVersionUpgrade());
        assertEquals(false, restarted.getDbInstance("disabled").isAutoMinorVersionUpgrade());
        assertEquals(true, restarted.getDbInstance("enabled").isAutoMinorVersionUpgrade());
    }

    @Test
    void legacyInstanceWithoutAutoMinorVersionFieldDefaultsToEnabled(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("rds-instances.json"), """
                {
                  "legacy": {
                    "dbInstanceIdentifier": "legacy",
                    "engine": "POSTGRES",
                    "status": "AVAILABLE",
                    "tags": {}
                  }
                }
                """);

        RdsService service = newService(dir);

        assertEquals(true, service.getDbInstance("legacy").isAutoMinorVersionUpgrade());
    }

    @Test
    void resolvedDefaultManagedMasterSecretKmsKeySurvivesRestart(@TempDir Path dir) {
        SecretsManagerService secretsManager = mock(SecretsManagerService.class);
        Secret secret = new Secret();
        secret.setArn("arn:aws:secretsmanager:us-west-2:123456789012:secret:rds!managed");
        when(secretsManager.createSecret(any(), any(), eq(null), any(), eq(null), eq(null), eq("us-west-2")))
                .thenReturn(secret);
        RdsService first = newService(dir, secretsManager);

        DbInstance created = first.createDbInstance(
                "managed", "postgres", "16.3", "admin", null, "app",
                "db.t3.micro", 20, false, null, null, null, null, false,
                true, null, Map.of(), List.of(), "us-west-2", true);
        RdsService restarted = newService(dir);

        assertEquals(created.getMasterUserSecretKmsKeyId(),
                restarted.getDbInstance("managed").getMasterUserSecretKmsKeyId());
        assertTrue(created.getMasterUserSecretKmsKeyId()
                .startsWith("arn:aws:kms:us-west-2:123456789012:key/"));
    }

    private RdsService newService(Path dir) {
        return newService(dir, null);
    }

    private RdsService newService(Path dir, SecretsManagerService secretsManagerService) {
        Ec2Service ec2Service = mock(Ec2Service.class);
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.RdsServiceConfig rds = mock(EmulatorConfig.RdsServiceConfig.class);
        when(config.services()).thenReturn(services);
        when(services.rds()).thenReturn(rds);
        when(rds.mock()).thenReturn(true);
        when(rds.proxyBasePort()).thenReturn(7000);
        when(rds.proxyMaxPort()).thenReturn(7099);
        when(ec2Service.describeSubnets(any(), anyList(), any()))
                .thenAnswer(invocation -> {
                    String region = invocation.getArgument(0, String.class);
                    @SuppressWarnings("unchecked")
                    List<String> subnetIds = invocation.getArgument(1, List.class);
                    List<String> effectiveSubnetIds = subnetIds == null || subnetIds.isEmpty()
                            ? List.of("subnet-a", "subnet-b")
                            : subnetIds;
                    return effectiveSubnetIds.stream()
                            .map(id -> subnet(id, id.endsWith("a") ? region + "a" : region + "b"))
                            .toList();
                });
        return new RdsService(
                mock(RdsContainerManager.class),
                mock(RdsProxyManager.class),
                ec2Service,
                new RegionResolver("us-east-1", "123456789012"),
                config,
                load(dir, "rds-instances.json", new TypeReference<Map<String, DbInstance>>() {}),
                load(dir, "rds-clusters.json", new TypeReference<Map<String, DbCluster>>() {}),
                load(dir, "rds-parameter-groups.json", new TypeReference<Map<String, DbParameterGroup>>() {}),
                load(dir, "rds-cluster-parameter-groups.json",
                        new TypeReference<Map<String, DbClusterParameterGroup>>() {}),
                load(dir, "rds-subnet-groups.json", new TypeReference<Map<String, DbSubnetGroup>>() {}),
                secretsManagerService,
                null);
    }

    private static Subnet subnet(String id, String availabilityZone) {
        Subnet subnet = new Subnet();
        subnet.setSubnetId(id);
        subnet.setVpcId("vpc-application");
        subnet.setAvailabilityZone(availabilityZone);
        return subnet;
    }

    private static <V> StorageBackend<String, V> load(
            Path dir, String file, TypeReference<Map<String, V>> typeReference) {
        PersistentStorage<String, V> backend = new PersistentStorage<>(dir.resolve(file), typeReference);
        backend.load();
        return backend;
    }
}
