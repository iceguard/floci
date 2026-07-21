package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeSubnetsResponse;
import software.amazon.awssdk.services.ec2.model.Filter;
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.rds.model.CreateDbParameterGroupResponse;
import software.amazon.awssdk.services.rds.model.CreateDbSubnetGroupResponse;
import software.amazon.awssdk.services.rds.model.DescribeDbSubnetGroupsResponse;
import software.amazon.awssdk.services.rds.model.DescribeOrderableDbInstanceOptionsResponse;
import software.amazon.awssdk.services.rds.model.Tag;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("RDS Control Plane")
class RdsControlPlaneTest {

    private static RdsClient rds;
    private static String subnetGroupName;
    private static String parameterGroupName;
    private static List<String> subnetIds;

    @BeforeAll
    static void setup() {
        rds = TestFixtures.rdsClient();
        subnetGroupName = TestFixtures.uniqueName("rds-subnets");
        parameterGroupName = TestFixtures.uniqueName("rds-parameters");
        try (Ec2Client ec2 = TestFixtures.ec2Client()) {
            String defaultVpcId = ec2.describeVpcs(r -> r
                            .filters(f -> f.name("is-default").values("true")))
                    .vpcs().get(0).vpcId();
            DescribeSubnetsResponse response = ec2.describeSubnets(r -> r
                    .filters(Filter.builder().name("vpc-id").values(defaultVpcId).build()));
            subnetIds = response.subnets().stream()
                    .map(subnet -> subnet.subnetId())
                    .sorted()
                    .limit(2)
                    .toList();
        }
        assertThat(subnetIds).hasSizeGreaterThanOrEqualTo(2);
    }

    @AfterAll
    static void cleanup() {
        if (rds != null) {
            try {
                rds.deleteDBSubnetGroup(b -> b.dbSubnetGroupName(subnetGroupName));
            } catch (Exception e) {
                System.err.println("Could not delete SDK test DB subnet group: " + e.getMessage());
            }
            try {
                rds.deleteDBParameterGroup(b -> b.dbParameterGroupName(parameterGroupName));
            } catch (Exception e) {
                System.err.println("Could not delete SDK test DB parameter group: " + e.getMessage());
            }
            rds.close();
        }
    }

    @Test
    void sdkUnmarshalsDbSubnetGroupSubnets() {
        CreateDbSubnetGroupResponse createResponse = rds.createDBSubnetGroup(b -> b
                .dbSubnetGroupName(subnetGroupName)
                .dbSubnetGroupDescription("SDK subnet group shape")
                .subnetIds(subnetIds)
                .tags(
                        Tag.builder().key("normal").value("sdk-test").build(),
                        Tag.builder().key("omitted").build(),
                        Tag.builder().key("explicit-empty").value("").build()));

        assertThat(createResponse.dbSubnetGroup().subnets())
                .extracting("subnetIdentifier")
                .containsExactlyElementsOf(subnetIds);

        DescribeDbSubnetGroupsResponse describeResponse = rds.describeDBSubnetGroups(b -> b
                .dbSubnetGroupName(subnetGroupName));

        assertThat(describeResponse.dbSubnetGroups()).hasSize(1);
        assertThat(describeResponse.dbSubnetGroups().get(0).subnets())
                .extracting("subnetIdentifier")
                .containsExactlyElementsOf(subnetIds);
        String subnetGroupArn = describeResponse.dbSubnetGroups().get(0).dbSubnetGroupArn();
        rds.addTagsToResource(b -> b.resourceName(subnetGroupArn).tags(
                Tag.builder().key("added-normal").value("added").build(),
                Tag.builder().key("added-omitted").build(),
                Tag.builder().key("added-explicit-empty").value("").build()));

        assertThat(rds.listTagsForResource(b -> b.resourceName(subnetGroupArn)).tagList())
                .containsExactlyInAnyOrder(
                        Tag.builder().key("normal").value("sdk-test").build(),
                        Tag.builder().key("omitted").value("").build(),
                        Tag.builder().key("explicit-empty").value("").build(),
                        Tag.builder().key("added-normal").value("added").build(),
                        Tag.builder().key("added-omitted").value("").build(),
                        Tag.builder().key("added-explicit-empty").value("").build());
    }

    @Test
    void sdkRoundTripsDbParameterGroupTags() {
        CreateDbParameterGroupResponse created = rds.createDBParameterGroup(b -> b
                .dbParameterGroupName(parameterGroupName)
                .dbParameterGroupFamily("postgres16")
                .description("SDK parameter group tag shape")
                .tags(
                        Tag.builder().key("normal").value("sdk-test").build(),
                        Tag.builder().key("omitted").build(),
                        Tag.builder().key("explicit-empty").value("").build()));

        assertThat(created.dbParameterGroup().dbParameterGroupArn())
                .isEqualTo("arn:aws:rds:us-east-1:000000000000:pg:" + parameterGroupName);
        rds.addTagsToResource(b -> b.resourceName(created.dbParameterGroup().dbParameterGroupArn()).tags(
                Tag.builder().key("added-normal").value("added").build(),
                Tag.builder().key("added-omitted").build(),
                Tag.builder().key("added-explicit-empty").value("").build()));
        assertThat(rds.listTagsForResource(b -> b.resourceName(
                        created.dbParameterGroup().dbParameterGroupArn())).tagList())
                .containsExactlyInAnyOrder(
                        Tag.builder().key("normal").value("sdk-test").build(),
                        Tag.builder().key("omitted").value("").build(),
                        Tag.builder().key("explicit-empty").value("").build(),
                        Tag.builder().key("added-normal").value("added").build(),
                        Tag.builder().key("added-omitted").value("").build(),
                        Tag.builder().key("added-explicit-empty").value("").build());
    }

    @Test
    void sdkListsSyntheticDefaultSubnetGroupTagsInSignedRegion() {
        try (RdsClient westRds = RdsClient.builder()
                .endpointOverride(flociEndpoint())
                .region(Region.US_WEST_2)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .build()) {
            String defaultArn = "arn:aws:rds:us-west-2:000000000000:subgrp:default";
            westRds.addTagsToResource(b -> b.resourceName(defaultArn)
                    .tags(Tag.builder().key("example.io:owner").value("network").build()));

            assertThat(westRds.listTagsForResource(b -> b.resourceName(defaultArn)).tagList())
                    .containsExactly(Tag.builder().key("example.io:owner").value("network").build());
            assertThat(westRds.describeDBSubnetGroups().dbSubnetGroups())
                    .filteredOn(group -> "default".equals(group.dbSubnetGroupName()))
                    .hasSize(1);

            westRds.removeTagsFromResource(b -> b.resourceName(defaultArn).tagKeys("example.io:owner"));
            assertThat(westRds.listTagsForResource(b -> b.resourceName(defaultArn)).tagList()).isEmpty();
        }
    }

    @Test
    void sdkScopesSameParameterGroupNameBySignedRegion() {
        String sharedName = TestFixtures.uniqueName("rds-regional-parameters");
        try (RdsClient westRds = RdsClient.builder()
                .endpointOverride(flociEndpoint())
                .region(Region.US_WEST_2)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .build()) {
            try {
                rds.createDBParameterGroup(b -> b.dbParameterGroupName(sharedName)
                        .dbParameterGroupFamily("postgres16").description("east"));
                westRds.createDBParameterGroup(b -> b.dbParameterGroupName(sharedName)
                        .dbParameterGroupFamily("postgres16").description("west"));

                assertThat(rds.describeDBParameterGroups(b -> b.dbParameterGroupName(sharedName))
                        .dbParameterGroups().get(0).description()).isEqualTo("east");
                assertThat(westRds.describeDBParameterGroups(b -> b.dbParameterGroupName(sharedName))
                        .dbParameterGroups().get(0).description()).isEqualTo("west");
            } finally {
                try {
                    rds.deleteDBParameterGroup(b -> b.dbParameterGroupName(sharedName));
                } catch (Exception e) {
                    System.err.println("Could not delete east SDK test DB parameter group: " + e.getMessage());
                }
                try {
                    westRds.deleteDBParameterGroup(b -> b.dbParameterGroupName(sharedName));
                } catch (Exception e) {
                    System.err.println("Could not delete west SDK test DB parameter group: " + e.getMessage());
                }
            }
        }
    }

    @Test
    void sdkDiscoversCurrentSmallGravitonPostgresOption() {
        DescribeOrderableDbInstanceOptionsResponse response = rds.describeOrderableDBInstanceOptions(b -> b
                .engine("postgres")
                .engineVersion("16.14")
                .dbInstanceClass("db.t4g.small"));

        assertThat(response.orderableDBInstanceOptions()).hasSize(1);
        assertThat(response.orderableDBInstanceOptions().get(0).engine()).isEqualTo("postgres");
        assertThat(response.orderableDBInstanceOptions().get(0).engineVersion()).isEqualTo("16.14");
        assertThat(response.orderableDBInstanceOptions().get(0).dbInstanceClass()).isEqualTo("db.t4g.small");
    }

    @Test
    void sdkReadsAutoMinorVersionUpgradeAcrossCreateDescribeAndModify() {
        String instanceName = TestFixtures.uniqueName("rds-auto-minor");
        boolean created = false;
        try {
            var createResponse = rds.createDBInstance(b -> b
                    .dbInstanceIdentifier(instanceName)
                    .dbInstanceClass("db.t3.micro")
                    .engine("postgres")
                    .masterUsername("admin")
                    .masterUserPassword("secret123")
                    .dbName("app")
                    .allocatedStorage(20));
            created = true;

            assertThat(createResponse.dbInstance().autoMinorVersionUpgrade()).isTrue();
            assertThat(rds.modifyDBInstance(b -> b
                            .dbInstanceIdentifier(instanceName)
                            .masterUserPassword("changedSecret123"))
                    .dbInstance().autoMinorVersionUpgrade()).isTrue();
            assertThat(rds.modifyDBInstance(b -> b
                            .dbInstanceIdentifier(instanceName)
                            .autoMinorVersionUpgrade(false))
                    .dbInstance().autoMinorVersionUpgrade()).isFalse();
            assertThat(rds.describeDBInstances(b -> b.dbInstanceIdentifier(instanceName))
                    .dbInstances().get(0).autoMinorVersionUpgrade()).isFalse();
            assertThat(rds.modifyDBInstance(b -> b
                            .dbInstanceIdentifier(instanceName)
                            .autoMinorVersionUpgrade(true))
                    .dbInstance().autoMinorVersionUpgrade()).isTrue();
        } finally {
            if (created) {
                rds.deleteDBInstance(b -> b
                        .dbInstanceIdentifier(instanceName)
                        .skipFinalSnapshot(true));
            }
        }
    }

    @Test
    void sdkResolvesDefaultManagedMasterSecretKmsKeyWhenOmitted() {
        String instanceName = TestFixtures.uniqueName("rds-managed-secret");
        boolean created = false;
        try {
            var createdInstance = rds.createDBInstance(b -> b
                            .dbInstanceIdentifier(instanceName)
                            .dbInstanceClass("db.t3.micro")
                            .engine("postgres")
                            .masterUsername("admin")
                            .dbName("app")
                            .allocatedStorage(20)
                            .manageMasterUserPassword(true))
                    .dbInstance();
            created = true;

            assertThat(createdInstance.masterUserSecret()).isNotNull();
            assertThat(createdInstance.masterUserSecret().secretArn()).isNotBlank();
            String secretArn = createdInstance.masterUserSecret().secretArn();
            assertThat(createdInstance.masterUserSecret().secretStatus()).isEqualTo("active");
            assertThat(createdInstance.masterUserSecret().kmsKeyId())
                    .matches("arn:aws:kms:us-east-1:000000000000:key/[0-9a-f-]{36}");

            var describedInstance = rds.describeDBInstances(b -> b.dbInstanceIdentifier(instanceName))
                    .dbInstances().get(0);
            assertThat(describedInstance.masterUserSecret()).isEqualTo(createdInstance.masterUserSecret());

            try (SecretsManagerClient secretsManager = TestFixtures.secretsManagerClient()) {
                assertThat(secretsManager.describeSecret(b -> b
                                .secretId(secretArn))
                        .kmsKeyId()).isNull();
            }

            rds.deleteDBInstance(b -> b
                    .dbInstanceIdentifier(instanceName)
                    .skipFinalSnapshot(true));
            created = false;

            String deletedSecretArn = secretArn;
            try (SecretsManagerClient secretsManager = TestFixtures.secretsManagerClient()) {
                assertThatThrownBy(() -> secretsManager.describeSecret(b -> b.secretId(deletedSecretArn)))
                        .isInstanceOf(ResourceNotFoundException.class)
                        .satisfies(error -> assertThat(((ResourceNotFoundException) error).statusCode()).isEqualTo(400));
            }
        } finally {
            if (created) {
                rds.deleteDBInstance(b -> b
                        .dbInstanceIdentifier(instanceName)
                        .skipFinalSnapshot(true));
            }
        }
    }

    private static URI flociEndpoint() {
        String configured = System.getenv("FLOCI_ENDPOINT");
        return URI.create(configured == null || configured.isBlank() ? "http://localhost:4566" : configured);
    }
}
