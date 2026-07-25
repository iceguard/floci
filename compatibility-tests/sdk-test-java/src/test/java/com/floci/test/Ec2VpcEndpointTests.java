package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.GroupIdentifier;
import software.amazon.awssdk.services.ec2.model.IpAddressType;
import software.amazon.awssdk.services.ec2.model.NetworkInterface;
import software.amazon.awssdk.services.ec2.model.ResourceType;
import software.amazon.awssdk.services.ec2.model.SecurityGroupIdentifier;
import software.amazon.awssdk.services.ec2.model.State;
import software.amazon.awssdk.services.ec2.model.Subnet;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ec2.model.TagSpecification;
import software.amazon.awssdk.services.ec2.model.VpcEndpoint;
import software.amazon.awssdk.services.ec2.model.VpcEndpointType;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

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

        VpcEndpoint createdGateway = ec2.createVpcEndpoint(request -> request
                        .vpcId(vpcId)
                        .serviceName("com.amazonaws.us-east-1.s3")
                        .vpcEndpointType(VpcEndpointType.GATEWAY)
                        .ipAddressType(IpAddressType.IPV4)
                        .routeTableIds(firstRouteTableId)
                        .policyDocument("{\"Version\":\"2012-10-17\"}")
                        .tagSpecifications(TagSpecification.builder()
                                .resourceType(ResourceType.VPC_ENDPOINT)
                                .tags(Tag.builder().key("Name").value("sdk-gateway").build())
                                .build()))
                .vpcEndpoint();
        assertThat(createdGateway.state()).isEqualTo(State.AVAILABLE);
        assertThat(createdGateway.stateAsString()).isEqualTo("Available");
        assertThat(createdGateway.ipAddressType()).isEqualTo(IpAddressType.IPV4);
        String gatewayId = createdGateway.vpcEndpointId();
        VpcEndpoint createdInterface = ec2.createVpcEndpoint(request -> request
                        .vpcId(vpcId)
                        .serviceName("com.amazonaws.us-east-1.secretsmanager")
                        .vpcEndpointType(VpcEndpointType.INTERFACE)
                        .ipAddressType(IpAddressType.IPV4)
                        .subnetIds(firstSubnetId, secondSubnetId)
                        .securityGroupIds(firstGroupId)
                        .privateDnsEnabled(true))
                .vpcEndpoint();
        assertThat(createdInterface.state()).isEqualTo(State.AVAILABLE);
        assertThat(createdInterface.stateAsString()).isEqualTo("Available");
        assertThat(createdInterface.ipAddressType()).isEqualTo(IpAddressType.IPV4);
        assertThat(createdInterface.networkInterfaceIds()).hasSize(2);
        assertThat(createdInterface.dnsEntries()).isNotEmpty();
        assertInterfacePlacement(
                createdInterface.networkInterfaceIds(),
                vpcId,
                List.of(firstSubnetId, secondSubnetId),
                firstGroupId);
        String interfaceId = createdInterface.vpcEndpointId();
        List<String> initialInterfaceIds = createdInterface.networkInterfaceIds();

        ec2.modifyVpcEndpoint(request -> request
                .vpcEndpointId(gatewayId)
                .removeRouteTableIds(firstRouteTableId)
                .addRouteTableIds(secondRouteTableId)
                .policyDocument("{\"Statement\":[]}"));
        ec2.modifyVpcEndpoint(request -> request
                .vpcEndpointId(interfaceId)
                .removeSubnetIds(firstSubnetId)
                .removeSecurityGroupIds(firstGroupId)
                .addSecurityGroupIds(secondGroupId)
                .privateDnsEnabled(false));

        List<VpcEndpoint> endpoints = ec2.describeVpcEndpoints(request -> request
                        .vpcEndpointIds(gatewayId, interfaceId))
                .vpcEndpoints();
        VpcEndpoint gateway = endpoint(endpoints, gatewayId);
        assertThat(gateway.state()).isEqualTo(State.AVAILABLE);
        assertThat(gateway.stateAsString()).isEqualTo("Available");
        assertThat(gateway.ipAddressType()).isEqualTo(IpAddressType.IPV4);
        assertThat(gateway.routeTableIds()).containsExactly(secondRouteTableId);
        assertThat(gateway.policyDocument()).isEqualTo("{\"Statement\":[]}");
        assertThat(gateway.tags()).extracting(Tag::key, Tag::value)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("Name", "sdk-gateway"));

        VpcEndpoint iface = endpoint(endpoints, interfaceId);
        assertThat(iface.state()).isEqualTo(State.AVAILABLE);
        assertThat(iface.stateAsString()).isEqualTo("Available");
        assertThat(iface.ipAddressType()).isEqualTo(IpAddressType.IPV4);
        assertThat(iface.subnetIds()).containsExactly(secondSubnetId);
        assertThat(iface.networkInterfaceIds()).hasSize(1);
        assertThat(iface.networkInterfaceIds()).isSubsetOf(initialInterfaceIds);
        assertThat(iface.groups()).extracting(SecurityGroupIdentifier::groupId)
                .containsExactly(secondGroupId);
        assertThat(iface.privateDnsEnabled()).isFalse();
        assertInterfacePlacement(
                iface.networkInterfaceIds(),
                vpcId,
                List.of(secondSubnetId),
                secondGroupId);
        String removedInterfaceId = initialInterfaceIds.stream()
                .filter(id -> !iface.networkInterfaceIds().contains(id))
                .findFirst()
                .orElseThrow();
        assertNetworkInterfacesAbsent(List.of(removedInterfaceId));

        ec2.deleteVpcEndpoints(request -> request.vpcEndpointIds(gatewayId, interfaceId));
        assertThatThrownBy(() -> ec2.describeVpcEndpoints(request -> request
                        .vpcEndpointIds(gatewayId)))
                .isInstanceOfSatisfying(Ec2Exception.class, error ->
                        assertThat(error.awsErrorDetails().errorCode())
                                .isEqualTo("InvalidVpcEndpointId.NotFound"));
        assertNetworkInterfacesAbsent(iface.networkInterfaceIds());

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

    private static void assertInterfacePlacement(
            List<String> networkInterfaceIds,
            String vpcId,
            List<String> subnetIds,
            String securityGroupId) {
        Map<String, NetworkInterface> interfacesBySubnet = ec2.describeNetworkInterfaces(request -> request
                        .networkInterfaceIds(networkInterfaceIds))
                .networkInterfaces()
                .stream()
                .collect(Collectors.toMap(NetworkInterface::subnetId, Function.identity()));
        assertThat(interfacesBySubnet.keySet()).containsExactlyInAnyOrderElementsOf(subnetIds);
        assertThat(interfacesBySubnet.values()).allSatisfy(networkInterface -> {
            assertThat(networkInterface.vpcId()).isEqualTo(vpcId);
            assertThat(networkInterface.interfaceTypeAsString()).isEqualTo("vpc_endpoint");
            assertThat(networkInterface.groups())
                    .extracting(GroupIdentifier::groupId)
                    .containsExactly(securityGroupId);
        });

        List<Subnet> subnets = ec2.describeSubnets(request -> request.subnetIds(subnetIds))
                .subnets();
        assertThat(subnets).extracting(Subnet::availabilityZoneId)
                .doesNotContainNull()
                .doesNotHaveDuplicates();
    }

    private static void assertNetworkInterfacesAbsent(List<String> networkInterfaceIds) {
        for (String networkInterfaceId : networkInterfaceIds) {
            assertThatThrownBy(() -> ec2.describeNetworkInterfaces(request -> request
                            .networkInterfaceIds(networkInterfaceId)))
                    .isInstanceOfSatisfying(Ec2Exception.class, error ->
                            assertThat(error.awsErrorDetails().errorCode())
                                    .isEqualTo("InvalidNetworkInterfaceID.NotFound"));
        }
    }
}
