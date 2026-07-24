package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import io.vertx.core.Vertx;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProviderChain;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;

import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class Ec2ImdsCredentialsSdkIntegrationTest {

    @Test
    void isolatedMetadataEndpointsPreserveInstanceIdentityAcrossLoopbackNat() throws Exception {
        int port = availablePort();
        Vertx vertx = Vertx.vertx();
        Ec2MetadataServer server = new Ec2MetadataServer(vertx, config(port), iamServiceWithRole());
        server.start().get(5, TimeUnit.SECONDS);

        Instance first = instanceWithProfile();
        Instance second = instanceWithProfile();
        second.setInstanceId("i-fedcba98765432100");
        server.registerContainer("172.18.0.11", first.getInstanceId(), first);
        server.registerContainer("172.18.0.12", second.getInstanceId(), second);

        try (HttpClient client = HttpClient.newHttpClient()) {
            int firstPort = server.registerInstanceEndpoint(first);
            int secondPort = server.registerInstanceEndpoint(second);

            assertEquals(first.getInstanceId(), metadataInstanceId(client, firstPort));
            assertEquals(second.getInstanceId(), metadataInstanceId(client, secondPort));
        }
        finally {
            server.stop();
            vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void awsSdkCredentialChainResolvesFlociInstanceProfileCredentials() throws Exception {
        int port = availablePort();
        Vertx vertx = Vertx.vertx();
        IamService iamService = iamServiceWithRole();
        Ec2MetadataServer server = new Ec2MetadataServer(vertx, config(port), iamService);
        Instance instance = instanceWithProfile();
        server.registerContainer("127.0.0.1", instance.getInstanceId(), instance);
        server.start().get(5, TimeUnit.SECONDS);

        try (InstanceProfileCredentialsProvider provider =
                     InstanceProfileCredentialsProvider.builder()
                             .endpoint("http://127.0.0.1:" + port)
                             .asyncCredentialUpdateEnabled(false)
                             .build()) {
            AwsCredentialsProviderChain chain = AwsCredentialsProviderChain.builder()
                    .credentialsProviders(provider)
                    .reuseLastProviderEnabled(false)
                    .build();

            AwsCredentials resolved = chain.resolveCredentials();
            AwsSessionCredentials session = assertInstanceOf(AwsSessionCredentials.class, resolved);
            Ec2MetadataServer.InstanceProfileCredentials cached =
                    server.cachedInstanceProfileCredentials(instance.getInstanceId()).orElseThrow();

            assertEquals(cached.accessKeyId(), session.accessKeyId());
            assertEquals(cached.secretAccessKey(), session.secretAccessKey());
            assertEquals(cached.token(), session.sessionToken());
            assertEquals(cached.accessKeyId(), chain.resolveCredentials().accessKeyId());
            verify(iamService, times(1)).registerSession(
                    eq(cached.accessKeyId()),
                    eq(cached.secretAccessKey()),
                    eq(cached.token()),
                    eq("arn:aws:iam::111122223333:role/sample-role"),
                    eq(instance.getInstanceId()),
                    eq("111122223333"),
                    eq("AROA0123456789ABCDEF"),
                    any(Instant.class),
                    isNull(),
                    eq("111122223333"));
        } finally {
            server.stop();
            vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        }
    }

    private static EmulatorConfig config(int port) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.Ec2ServiceConfig ec2 = mock(EmulatorConfig.Ec2ServiceConfig.class);
        when(config.services()).thenReturn(services);
        when(services.ec2()).thenReturn(ec2);
        when(ec2.imdsPort()).thenReturn(port);
        return config;
    }

    private static IamService iamServiceWithRole() {
        IamService iamService = mock(IamService.class);
        InstanceProfile profile = new InstanceProfile();
        profile.setInstanceProfileName("sample-profile");
        profile.setRoleNames(List.of("sample-role"));
        when(iamService.getInstanceProfile("sample-profile")).thenReturn(profile);
        IamRole role = new IamRole();
        role.setRoleId("AROA0123456789ABCDEF");
        role.setArn("arn:aws:iam::111122223333:role/sample-role");
        when(iamService.getRole("sample-role")).thenReturn(role);
        return iamService;
    }

    private static Instance instanceWithProfile() {
        Instance instance = new Instance();
        instance.setInstanceId("i-0123456789abcdef0");
        instance.setIamInstanceProfileArn(
                "arn:aws:iam::111122223333:instance-profile/sample-profile");
        return instance;
    }

    private static int availablePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static String metadataInstanceId(HttpClient client, int port) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + port + "/latest/meta-data/instance-id"))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }
}
