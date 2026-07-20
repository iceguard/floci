package io.github.hectorvent.floci.services.ec2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.Placement;
import io.github.hectorvent.floci.services.ec2.model.Tag;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class Ec2MetadataServerTest {

    @Test
    void instanceMetadataListsTagKeys() {
        Instance instance = new Instance();
        instance.setTags(List.of(
                new Tag("Environment", "dev"),
                new Tag("Service", "orders")));

        assertEquals("Environment\nService", Ec2MetadataServer.instanceTagKeys(instance));
    }

    @Test
    void instanceMetadataReturnsTagValue() {
        Instance instance = new Instance();
        instance.setTags(List.of(
                new Tag("Environment", "dev"),
                new Tag("Service", "orders")));

        assertEquals("orders", Ec2MetadataServer.instanceTagValue(instance, "Service").orElseThrow());
    }

    @Test
    void instanceMetadataReturnsEmptyValueForEmptyTag() {
        Instance instance = new Instance();
        instance.setTags(List.of(new Tag("Owner", null)));

        assertTrue(Ec2MetadataServer.instanceTagValue(instance, "Owner").isPresent());
        assertEquals("", Ec2MetadataServer.instanceTagValue(instance, "Owner").orElseThrow());
    }

    @Test
    void instanceMetadataReturnsMissingForUnknownTag() {
        Instance instance = new Instance();
        instance.setTags(List.of(new Tag("Environment", "dev")));

        assertTrue(Ec2MetadataServer.instanceTagValue(instance, "Missing").isEmpty());
    }

    @Test
    void identityDocumentUsesInstanceArchitectureWithX8664Fallback() {
        Instance instance = new Instance();
        instance.setInstanceId("i-arm");
        instance.setArchitecture("arm64");
        instance.setImageId("ami-arm");
        instance.setInstanceType("t4g.medium");
        instance.setPlacement(new Placement("us-west-2a"));
        instance.setPrivateIpAddress("10.0.0.10");
        instance.setRegion("us-west-2");

        assertTrue(Ec2MetadataServer.instanceIdentityDocument(instance, "000000000000")
                .contains("\"architecture\":\"arm64\""));

        instance.setArchitecture(null);
        assertTrue(Ec2MetadataServer.instanceIdentityDocument(instance, "000000000000")
                .contains("\"architecture\":\"x86_64\""));
    }

    @Test
    void staleContainerUnregisterDoesNotRemoveCurrentRegistration() {
        Ec2MetadataServer server = new Ec2MetadataServer(null, null, null);
        Instance oldInstance = new Instance();
        oldInstance.setInstanceId("i-old");
        Instance currentInstance = new Instance();
        currentInstance.setInstanceId("i-current");

        server.registerContainer("192.168.215.7", oldInstance.getInstanceId(), oldInstance);
        server.registerContainer("192.168.215.7", currentInstance.getInstanceId(), currentInstance);
        server.unregisterContainer("192.168.215.7", oldInstance);

        assertEquals(
                currentInstance,
                server.registeredContainer("192.168.215.7").orElseThrow());
    }

    @Test
    void iamCredentialRoleNameComesFromInstanceProfileRole() {
        IamService iamService = mock(IamService.class);
        InstanceProfile profile = new InstanceProfile();
        profile.setInstanceProfileName("sample-profile");
        profile.setRoleNames(List.of("sample-role"));
        when(iamService.getInstanceProfile("sample-profile")).thenReturn(profile);

        Ec2MetadataServer server = new Ec2MetadataServer(null, null, iamService);

        assertEquals("sample-role", server.resolveRoleName(
                "arn:aws:iam::000000000000:instance-profile/sample-profile"));
    }

    @Test
    void instanceProfileCredentialsHaveAwsShapeAndStableJson() throws Exception {
        Ec2MetadataServer server = serverWithRole(mock(IamService.class));
        Instance instance = instanceWithProfile("i-0123456789abcdef0");
        Instant issuedAt = Instant.parse("2026-07-19T12:00:00Z");

        Ec2MetadataServer.InstanceProfileCredentials credentials =
                server.issueInstanceProfileCredentials(instance, issuedAt);

        assertTrue(credentials.accessKeyId().matches("ASIA[A-F0-9]{16}"));
        assertTrue(credentials.secretAccessKey().matches("[A-Za-z0-9/+=]{40}"));
        assertTrue(credentials.token().matches("[A-Za-z0-9/+=]{64,}"));
        assertEquals(issuedAt, credentials.lastUpdated());
        assertEquals(issuedAt.plusSeconds(3600), credentials.expiration());

        JsonNode document = new ObjectMapper().readTree(credentials.toJson());
        assertEquals(7, document.size());
        assertEquals("Success", document.path("Code").asText());
        assertEquals("AWS-HMAC", document.path("Type").asText());
        assertEquals(credentials.accessKeyId(), document.path("AccessKeyId").asText());
        assertEquals(credentials.secretAccessKey(), document.path("SecretAccessKey").asText());
        assertEquals(credentials.token(), document.path("Token").asText());
        assertEquals("2026-07-19T12:00:00Z", document.path("LastUpdated").asText());
        assertEquals("2026-07-19T13:00:00Z", document.path("Expiration").asText());
    }

    @Test
    void credentialsAreCachedRotatedWithOverlapAndRevokedOnTeardown() {
        IamService iamService = mock(IamService.class);
        Ec2MetadataServer server = serverWithRole(iamService);
        Instance instance = instanceWithProfile("i-0123456789abcdef0");
        Instant issuedAt = Instant.parse("2030-07-19T12:00:00Z");

        Ec2MetadataServer.InstanceProfileCredentials first =
                server.issueInstanceProfileCredentials(instance, issuedAt);
        Ec2MetadataServer.InstanceProfileCredentials cached =
                server.issueInstanceProfileCredentials(instance, issuedAt.plusSeconds(30 * 60));
        Ec2MetadataServer.InstanceProfileCredentials rotated =
                server.issueInstanceProfileCredentials(instance, issuedAt.plusSeconds(56 * 60));

        assertEquals(first, cached);
        assertNotEquals(first.accessKeyId(), rotated.accessKeyId());
        assertEquals(rotated,
                server.cachedInstanceProfileCredentials(instance.getInstanceId()).orElseThrow());
        verify(iamService, times(2)).registerSession(
                anyString(),
                anyString(),
                anyString(),
                eq("arn:aws:iam::111122223333:role/sample-role"),
                eq(instance.getInstanceId()),
                eq("111122223333"),
                eq("AROA0123456789ABCDEF"),
                any(Instant.class),
                isNull(),
                eq("111122223333"));
        verify(iamService, never()).unregisterSession(anyString());

        Ec2MetadataServer.InstanceProfileCredentials next =
                server.issueInstanceProfileCredentials(instance, issuedAt.plusSeconds(117 * 60));

        verify(iamService).unregisterSession(first.accessKeyId());
        assertNotEquals(rotated.accessKeyId(), next.accessKeyId());

        server.unregisterInstance(instance);

        verify(iamService).unregisterSession(rotated.accessKeyId());
        verify(iamService).unregisterSession(next.accessKeyId());
        assertFalse(server.cachedInstanceProfileCredentials(instance.getInstanceId()).isPresent());

        Ec2MetadataServer.InstanceProfileCredentials afterTeardown =
                server.issueInstanceProfileCredentials(instance, issuedAt.plusSeconds(118 * 60));
        assertNotEquals(next.accessKeyId(), afterTeardown.accessKeyId());
    }

    private static Ec2MetadataServer serverWithRole(IamService iamService) {
        InstanceProfile profile = new InstanceProfile();
        profile.setInstanceProfileName("sample-profile");
        profile.setRoleNames(List.of("sample-role"));
        when(iamService.getInstanceProfile("sample-profile")).thenReturn(profile);
        IamRole role = new IamRole();
        role.setRoleId("AROA0123456789ABCDEF");
        role.setArn("arn:aws:iam::111122223333:role/sample-role");
        when(iamService.getRole("sample-role")).thenReturn(role);
        return new Ec2MetadataServer(null, null, iamService);
    }

    private static Instance instanceWithProfile(String instanceId) {
        Instance instance = new Instance();
        instance.setInstanceId(instanceId);
        instance.setIamInstanceProfileArn(
                "arn:aws:iam::111122223333:instance-profile/sample-profile");
        return instance;
    }
}
