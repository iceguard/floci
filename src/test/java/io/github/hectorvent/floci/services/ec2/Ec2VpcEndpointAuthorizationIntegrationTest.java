package io.github.hectorvent.floci.services.ec2;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.CreateVpcEndpointResponse;
import software.amazon.awssdk.services.ec2.model.Ec2Exception;
import software.amazon.awssdk.services.ec2.model.IpAddressType;
import software.amazon.awssdk.services.ec2.model.ResourceType;
import software.amazon.awssdk.services.ec2.model.State;
import software.amazon.awssdk.services.ec2.model.Tag;
import software.amazon.awssdk.services.ec2.model.TagSpecification;
import software.amazon.awssdk.services.ec2.model.VpcEndpoint;
import software.amazon.awssdk.services.ec2.model.VpcEndpointType;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(Ec2VpcEndpointAuthorizationIntegrationTest.IamEnforcementProfile.class)
class Ec2VpcEndpointAuthorizationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-east-1";
    private static final String DEFINITION_TAG = "example.io:definition-id";
    private static final String MANAGED_BY_TAG = "example.io:managed-by";

    @Test
    void authorizesTaggedCreateModifyTagAndDeleteAgainstVpcEndpointArns() {
        try (Ec2Client root = rootClient()) {
            EndpointFixture fixture = createGatewayFixture(root, "floci");
            SessionCredentials credentials = createSession("floci", true, true, true);
            try (Ec2Client scoped = ec2Client(credentials)) {
                CreateVpcEndpointResponse created = createTaggedGatewayEndpoint(
                        scoped, fixture, "floci");
                assertEquals(State.AVAILABLE, created.vpcEndpoint().state());
                assertEquals("Available", created.vpcEndpoint().stateAsString());
                assertEquals(IpAddressType.IPV4, created.vpcEndpoint().ipAddressType());
                String endpointId = created.vpcEndpoint().vpcEndpointId();

                scoped.modifyVpcEndpoint(request -> request
                        .vpcEndpointId(endpointId)
                        .removeRouteTableIds(fixture.firstRouteTableId())
                        .addRouteTableIds(fixture.secondRouteTableId())
                        .policyDocument("{\"Statement\":[]}"));
                scoped.createTags(request -> request
                        .resources(endpointId)
                        .tags(Tag.builder().key("example.io:updated").value("true").build()));

                VpcEndpoint modified = endpoint(root, endpointId);
                assertEquals(State.AVAILABLE, modified.state());
                assertEquals("Available", modified.stateAsString());
                assertEquals(IpAddressType.IPV4, modified.ipAddressType());
                assertEquals(List.of(fixture.secondRouteTableId()), modified.routeTableIds());
                assertEquals("{\"Statement\":[]}", modified.policyDocument());
                assertTrue(modified.tags().stream().anyMatch(tag ->
                        "example.io:updated".equals(tag.key()) && "true".equals(tag.value())));

                scoped.deleteVpcEndpoints(request -> request.vpcEndpointIds(endpointId));
                assertFalse(endpointExists(root, endpointId));
            }
        }
    }

    @Test
    void rejectsTaggedCreateWithoutSupplementalCreateTagsPermissionWithoutMutation() {
        try (Ec2Client root = rootClient()) {
            EndpointFixture fixture = createGatewayFixture(root, "floci");
            SessionCredentials credentials = createSession("floci", false, true, true);
            try (Ec2Client scoped = ec2Client(credentials)) {
                int before = endpointCount(root, fixture.vpcId());

                Ec2Exception denied = assertThrows(Ec2Exception.class,
                        () -> createTaggedGatewayEndpoint(scoped, fixture, "floci"));

                assertAccessDenied(denied, "ec2:CreateTags");
                assertEquals(before, endpointCount(root, fixture.vpcId()));
            }
        }
    }

    @Test
    void rejectsWrongTagAndMissingPermissionWithoutChangingOrDeletingEndpoints() {
        try (Ec2Client root = rootClient()) {
            EndpointFixture fixture = createGatewayFixture(root, "other");
            String wrongTagEndpoint = createTaggedGatewayEndpoint(
                    root, fixture, "other").vpcEndpoint().vpcEndpointId();
            String protectedEndpoint = createTaggedGatewayEndpoint(
                    root, fixture, "floci").vpcEndpoint().vpcEndpointId();
            SessionCredentials scopedCredentials = createSession("floci", true, true, true);
            SessionCredentials noModifyCredentials = createSession("floci", true, false, true);

            try (Ec2Client scoped = ec2Client(scopedCredentials);
                    Ec2Client noModify = ec2Client(noModifyCredentials)) {
                Ec2Exception wrongTag = assertThrows(Ec2Exception.class,
                        () -> scoped.modifyVpcEndpoint(request -> request
                                .vpcEndpointId(wrongTagEndpoint)
                                .removeRouteTableIds(fixture.firstRouteTableId())
                                .addRouteTableIds(fixture.secondRouteTableId())));
                assertAccessDenied(wrongTag, "ec2:ModifyVpcEndpoint");
                assertEquals(
                        List.of(fixture.firstRouteTableId()),
                        endpoint(root, wrongTagEndpoint).routeTableIds());

                Ec2Exception missingPermission = assertThrows(Ec2Exception.class,
                        () -> noModify.modifyVpcEndpoint(request -> request
                                .vpcEndpointId(protectedEndpoint)
                                .removeRouteTableIds(fixture.firstRouteTableId())
                                .addRouteTableIds(fixture.secondRouteTableId())));
                assertAccessDenied(missingPermission, "ec2:ModifyVpcEndpoint");
                assertEquals(
                        List.of(fixture.firstRouteTableId()),
                        endpoint(root, protectedEndpoint).routeTableIds());

                Ec2Exception multiDelete = assertThrows(Ec2Exception.class,
                        () -> scoped.deleteVpcEndpoints(request -> request
                                .vpcEndpointIds(protectedEndpoint, wrongTagEndpoint)));
                assertAccessDenied(multiDelete, "ec2:DeleteVpcEndpoints");
                assertTrue(endpointExists(root, protectedEndpoint));
                assertTrue(endpointExists(root, wrongTagEndpoint));
            }
        }
    }

    private static EndpointFixture createGatewayFixture(Ec2Client root, String suffix) {
        String unique = suffix + "-" + UUID.randomUUID().toString().substring(0, 8);
        String vpcId = root.createVpc(request -> request.cidrBlock("10.90.0.0/16"))
                .vpc()
                .vpcId();
        String firstRouteTableId = root.createRouteTable(
                        request -> request.vpcId(vpcId))
                .routeTable()
                .routeTableId();
        String secondRouteTableId = root.createRouteTable(
                        request -> request.vpcId(vpcId))
                .routeTable()
                .routeTableId();
        return new EndpointFixture(
                vpcId,
                firstRouteTableId,
                secondRouteTableId,
                "com.amazonaws." + REGION + ".s3-" + unique);
    }

    private static CreateVpcEndpointResponse createTaggedGatewayEndpoint(
            Ec2Client client, EndpointFixture fixture, String managedBy) {
        return client.createVpcEndpoint(request -> request
                .vpcId(fixture.vpcId())
                .serviceName(fixture.serviceName())
                .vpcEndpointType(VpcEndpointType.GATEWAY)
                .ipAddressType(IpAddressType.IPV4)
                .routeTableIds(fixture.firstRouteTableId())
                .tagSpecifications(TagSpecification.builder()
                        .resourceType(ResourceType.VPC_ENDPOINT)
                        .tags(
                                Tag.builder().key(DEFINITION_TAG).value("example").build(),
                                Tag.builder().key(MANAGED_BY_TAG).value(managedBy).build())
                        .build()));
    }

    private static VpcEndpoint endpoint(Ec2Client root, String endpointId) {
        return root.describeVpcEndpoints(request -> request.vpcEndpointIds(endpointId))
                .vpcEndpoints()
                .getFirst();
    }

    private static boolean endpointExists(Ec2Client root, String endpointId) {
        return root.describeVpcEndpoints().vpcEndpoints().stream()
                .anyMatch(endpoint -> endpointId.equals(endpoint.vpcEndpointId()));
    }

    private static int endpointCount(Ec2Client root, String vpcId) {
        return (int) root.describeVpcEndpoints().vpcEndpoints().stream()
                .filter(endpoint -> vpcId.equals(endpoint.vpcId()))
                .count();
    }

    private static SessionCredentials createSession(
            String managedBy,
            boolean allowCreateTags,
            boolean allowModify,
            boolean allowDelete) {
        String roleName = "VpcEndpointRole" + UUID.randomUUID().toString().substring(0, 8);
        createRole(roleName);
        String createTags = allowCreateTags ? """
                , {
                  "Effect": "Allow",
                  "Action": "ec2:CreateTags",
                  "Resource": "arn:aws:ec2:%s:%s:vpc-endpoint/*",
                  "Condition": {"StringEquals": {
                    "aws:RequestTag/%s": "example",
                    "aws:RequestTag/%s": "%s",
                    "ec2:CreateAction": "CreateVpcEndpoint"
                  }}
                }, {
                  "Effect": "Allow",
                  "Action": "ec2:CreateTags",
                  "Resource": "arn:aws:ec2:%s:%s:vpc-endpoint/*",
                  "Condition": {"StringEquals": {
                    "aws:ResourceTag/%s": "example",
                    "aws:ResourceTag/%s": "%s"
                  }}
                }
                """.formatted(
                REGION, ACCOUNT_ID, DEFINITION_TAG, MANAGED_BY_TAG, managedBy,
                REGION, ACCOUNT_ID, DEFINITION_TAG, MANAGED_BY_TAG, managedBy) : "";
        String modify = allowModify ? """
                , {
                  "Effect": "Allow",
                  "Action": "ec2:ModifyVpcEndpoint",
                  "Resource": "arn:aws:ec2:%s:%s:vpc-endpoint/*",
                  "Condition": {"StringEquals": {
                    "aws:RequestedRegion": "%s",
                    "aws:ResourceTag/%s": "example",
                    "aws:ResourceTag/%s": "%s"
                  }}
                }
                """.formatted(
                REGION, ACCOUNT_ID, REGION, DEFINITION_TAG, MANAGED_BY_TAG, managedBy) : "";
        String delete = allowDelete ? """
                , {
                  "Effect": "Allow",
                  "Action": "ec2:DeleteVpcEndpoints",
                  "Resource": "arn:aws:ec2:%s:%s:vpc-endpoint/*",
                  "Condition": {"StringEquals": {
                    "aws:RequestedRegion": "%s",
                    "aws:ResourceTag/%s": "example",
                    "aws:ResourceTag/%s": "%s"
                  }}
                }
                """.formatted(
                REGION, ACCOUNT_ID, REGION, DEFINITION_TAG, MANAGED_BY_TAG, managedBy) : "";
        putRolePolicy(roleName, """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "ec2:CreateVpcEndpoint",
                    "Resource": "arn:aws:ec2:%s:%s:vpc-endpoint/*",
                    "Condition": {"StringEquals": {
                      "aws:RequestedRegion": "%s",
                      "aws:RequestTag/%s": "example",
                      "aws:RequestTag/%s": "%s"
                    }}
                  }%s%s%s]
                }
                """.formatted(
                REGION, ACCOUNT_ID, REGION, DEFINITION_TAG, MANAGED_BY_TAG, managedBy,
                createTags, modify, delete));
        return assumeRole(roleName);
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument", """
                        {"Version":"2012-10-17","Statement":[{
                          "Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"
                        }]}
                        """)
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    private static void putRolePolicy(String roleName, String policyDocument) {
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "ScopedVpcEndpointLifecycle")
                .formParam("PolicyDocument", policyDocument)
                .header("Authorization", auth(ACCOUNT_ID, "iam"))
        .when().post("/")
        .then().statusCode(200);
    }

    private static SessionCredentials assumeRole(String roleName) {
        io.restassured.response.Response response = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT_ID + ":role/" + roleName)
                .formParam("RoleSessionName", "vpc-endpoint-authorization-test")
                .header("Authorization", auth(ACCOUNT_ID, "sts"))
        .when().post("/")
        .then().statusCode(200)
                .extract().response();
        return new SessionCredentials(
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SecretAccessKey"),
                response.path("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private static Ec2Client rootClient() {
        return ec2Client(ACCOUNT_ID, "secret", null);
    }

    private static Ec2Client ec2Client(SessionCredentials credentials) {
        return ec2Client(
                credentials.accessKeyId(),
                credentials.secretAccessKey(),
                credentials.sessionToken());
    }

    private static Ec2Client ec2Client(
            String accessKeyId, String secretAccessKey, String sessionToken) {
        var credentials = sessionToken == null
                ? AwsBasicCredentials.create(accessKeyId, secretAccessKey)
                : AwsSessionCredentials.create(accessKeyId, secretAccessKey, sessionToken);
        return Ec2Client.builder()
                .endpointOverride(URI.create("http://localhost:" + RestAssured.port))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .build();
    }

    private static void assertAccessDenied(Ec2Exception exception, String action) {
        assertEquals(403, exception.statusCode());
        assertEquals("UnauthorizedOperation", exception.awsErrorDetails().errorCode());
        assertTrue(exception.getMessage().contains(action));
        assertNotNull(exception.requestId());
    }

    private static String auth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260725/" + REGION + "/" + service
                + "/aws4_request, SignedHeaders=host, Signature=abc";
    }

    private record EndpointFixture(
            String vpcId,
            String firstRouteTableId,
            String secondRouteTableId,
            String serviceName) {}

    private record SessionCredentials(
            String accessKeyId,
            String secretAccessKey,
            String sessionToken) {}

    public static final class IamEnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.iam.enforcement-enabled", "true");
        }
    }
}
