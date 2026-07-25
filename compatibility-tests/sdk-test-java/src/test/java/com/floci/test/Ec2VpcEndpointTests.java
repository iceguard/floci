package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.ResourceType;
import software.amazon.awssdk.services.ec2.model.SecurityGroupIdentifier;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ec2.model.TagSpecification;
import software.amazon.awssdk.services.ec2.model.VpcEndpoint;
import software.amazon.awssdk.services.ec2.model.VpcEndpointType;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EC2 VPC endpoints")
class Ec2VpcEndpointTests {

    private static Ec2Client ec2;

    @BeforeAll
    static void setup() {
        ec2 = TestFixtures.ec2Client();
    }

    @AfterAll
    static void close() {
        ec2.close();
    }

    @Test
    void gatewayAndInterfaceEndpointsRoundTripThroughTheOfficialSdk() {
        String vpcId = ec2.createVpc(request -> request.cidrBlock("10.91.0.0/16"))
                .vpc()
                .vpcId();
        String firstRouteTableId = ec2.createRouteTable(request -> request.vpcId(vpcId))
                .routeTable()
                .routeTableId();
        String secondRouteTableId = ec2.createRouteTable(request -> request.vpcId(vpcId))
                .routeTable()
                .routeTableId();
        String firstSubnetId = ec2.createSubnet(request -> request
                        .vpcId(vpcId)
                        .cidrBlock("10.91.1.0/24")
                        .availabilityZone("us-east-1a"))
                .subnet()
                .subnetId();
        String secondSubnetId = ec2.createSubnet(request -> request
                        .vpcId(vpcId)
                        .cidrBlock("10.91.2.0/24")
                        .availabilityZone("us-east-1b"))
                .subnet()
                .subnetId();
        String firstGroupId = createSecurityGroup(vpcId, "first");
        String secondGroupId = createSecurityGroup(vpcId, "second");

        String gatewayId = ec2.createVpcEndpoint(request -> request
                        .vpcId(vpcId)
                        .serviceName("com.amazonaws.us-east-1.s3")
                        .vpcEndpointType(VpcEndpointType.GATEWAY)
                        .routeTableIds(firstRouteTableId)
                        .policyDocument("{\"Version\":\"2012-10-17\"}")
                        .tagSpecifications(TagSpecification.builder()
                                .resourceType(ResourceType.VPC_ENDPOINT)
                                .tags(Tag.builder().key("Name").value("sdk-gateway").build())
                                .build()))
                .vpcEndpoint()
                .vpcEndpointId();
        String interfaceId = ec2.createVpcEndpoint(request -> request
                        .vpcId(vpcId)
                        .serviceName("com.amazonaws.us-east-1.secretsmanager")
                        .vpcEndpointType(VpcEndpointType.INTERFACE)
                        .subnetIds(firstSubnetId)
                        .securityGroupIds(firstGroupId)
                        .privateDnsEnabled(true))
                .vpcEndpoint()
                .vpcEndpointId();

        ec2.modifyVpcEndpoint(request -> request
                .vpcEndpointId(gatewayId)
                .removeRouteTableIds(firstRouteTableId)
                .addRouteTableIds(secondRouteTableId)
                .policyDocument("{\"Statement\":[]}"));
        ec2.modifyVpcEndpoint(request -> request
                .vpcEndpointId(interfaceId)
                .removeSubnetIds(firstSubnetId)
                .addSubnetIds(secondSubnetId)
                .removeSecurityGroupIds(firstGroupId)
                .addSecurityGroupIds(secondGroupId)
                .privateDnsEnabled(false));

        List<VpcEndpoint> endpoints = ec2.describeVpcEndpoints(request -> request
                        .vpcEndpointIds(gatewayId, interfaceId))
                .vpcEndpoints();
        VpcEndpoint gateway = endpoint(endpoints, gatewayId);
        assertThat(gateway.routeTableIds()).containsExactly(secondRouteTableId);
        assertThat(gateway.policyDocument()).isEqualTo("{\"Statement\":[]}");
        assertThat(gateway.tags()).extracting(Tag::key, Tag::value)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("Name", "sdk-gateway"));

        VpcEndpoint iface = endpoint(endpoints, interfaceId);
        assertThat(iface.subnetIds()).containsExactly(secondSubnetId);
        assertThat(iface.groups()).extracting(SecurityGroupIdentifier::groupId)
                .containsExactly(secondGroupId);
        assertThat(iface.privateDnsEnabled()).isFalse();

        ec2.deleteVpcEndpoints(request -> request.vpcEndpointIds(gatewayId, interfaceId));
        assertThatThrownBy(() -> ec2.describeVpcEndpoints(request -> request
                        .vpcEndpointIds(gatewayId)))
                .isInstanceOfSatisfying(Ec2Exception.class, error ->
                        assertThat(error.awsErrorDetails().errorCode())
                                .isEqualTo("InvalidVpcEndpointId.NotFound"));

        ec2.deleteSecurityGroup(request -> request.groupId(firstGroupId));
        ec2.deleteSecurityGroup(request -> request.groupId(secondGroupId));
        ec2.deleteSubnet(request -> request.subnetId(firstSubnetId));
        ec2.deleteSubnet(request -> request.subnetId(secondSubnetId));
        ec2.deleteRouteTable(request -> request.routeTableId(firstRouteTableId));
        ec2.deleteRouteTable(request -> request.routeTableId(secondRouteTableId));
        ec2.deleteVpc(request -> request.vpcId(vpcId));
    }

    private static String createSecurityGroup(String vpcId, String suffix) {
        return ec2.createSecurityGroup(request -> request
                        .vpcId(vpcId)
                        .groupName("sdk-endpoint-" + suffix + "-" + System.nanoTime())
                        .description("SDK endpoint " + suffix + " group"))
                .groupId();
    }

    private static VpcEndpoint endpoint(List<VpcEndpoint> endpoints, String endpointId) {
        return endpoints.stream()
                .filter(endpoint -> endpointId.equals(endpoint.vpcEndpointId()))
                .findFirst()
                .orElseThrow();
    }
}
