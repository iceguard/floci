package io.github.hectorvent.floci.services.elbv2;

import io.github.hectorvent.floci.services.acm.AcmService;
import io.github.hectorvent.floci.services.acm.model.Certificate;
import io.github.hectorvent.floci.services.acm.model.CertificateOptions;
import io.github.hectorvent.floci.services.acm.model.KeyAlgorithm;
import io.github.hectorvent.floci.services.acm.model.ValidationMethod;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(ElbV2HttpsDataPlaneIntegrationTest.RealElbV2DataPlaneProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ElbV2HttpsDataPlaneIntegrationTest {

    public static final class RealElbV2DataPlaneProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.elbv2.mock", "false");
        }
    }

    private static final String REGION = "us-east-1";
    private static final String AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260720/us-east-1/elasticloadbalancing/aws4_request";
    private static final int HTTPS_PORT = 7794;
    private static final int HTTP_PORT = 7795;

    private static String firstLbArn;
    private static String firstTargetGroupArn;
    private static String firstListenerArn;
    private static String secondLbArn;
    private static String secondListenerArn;
    private static String httpLbArn;
    private static String httpListenerArn;
    private static com.sun.net.httpserver.HttpServer targetServer;

    @Inject
    AcmService acmService;

    @BeforeAll
    static void startTargetServer() throws IOException {
        targetServer = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        targetServer.createContext("/", exchange -> {
            byte[] response = "target".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(response);
            }
        });
        targetServer.start();
    }

    @AfterAll
    static void stopTargetServer() {
        if (targetServer != null) {
            targetServer.stop(0);
        }
    }

    @Test
    @Order(1)
    void terminatesTlsWithSniSelectedAcmCertificatesAndKeepsHttpListenersPlain() throws Exception {
        LoadBalancerRef first = createLoadBalancer("https-first");
        firstLbArn = first.arn();
        Certificate firstCertificate = requestCertificate(first.dnsName());
        firstTargetGroupArn = createHealthyTargetGroup();
        firstListenerArn = createForwardListener(
                first.arn(), HTTPS_PORT, firstCertificate.getArn(), firstTargetGroupArn);

        describeHttpsListener(firstListenerArn, firstCertificate.getArn());
        awaitTargetHealthy(firstTargetGroupArn);
        HttpsResult firstResult = awaitHttps(first.dnsName(), firstCertificate);
        assertEquals(200, firstResult.statusCode());
        assertEquals("target", firstResult.body());
        assertPeerCertificate(firstResult.session(), firstCertificate, first.dnsName());

        LoadBalancerRef second = createLoadBalancer("https-second");
        secondLbArn = second.arn();
        Certificate secondCertificate = requestCertificate(second.dnsName());
        secondListenerArn = createFixedResponseListener(
                second.arn(), "HTTPS", HTTPS_PORT, secondCertificate.getArn(), "second");

        HttpsResult refreshedFirstResult = awaitHttps(first.dnsName(), firstCertificate);
        assertEquals("target", refreshedFirstResult.body());
        assertPeerCertificate(refreshedFirstResult.session(), firstCertificate, first.dnsName());

        HttpsResult secondResult = awaitHttps(second.dnsName(), secondCertificate);
        assertEquals("second", secondResult.body());
        assertPeerCertificate(secondResult.session(), secondCertificate, second.dnsName());

        LoadBalancerRef http = createLoadBalancer("http-control");
        httpLbArn = http.arn();
        httpListenerArn = createFixedResponseListener(http.arn(), "HTTP", HTTP_PORT, null, "plain");
        given()
                .baseUri("http://" + http.dnsName())
                .port(HTTP_PORT)
            .when()
                .get("/")
            .then()
                .statusCode(200)
                .body(equalTo("plain"));

        deleteListener(firstListenerArn);
        firstListenerArn = null;
        assertEquals("second", awaitHttps(second.dnsName(), secondCertificate).body());

        deleteListener(secondListenerArn);
        secondListenerArn = null;
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            Exception failure = assertThrows(Exception.class,
                    () -> trustedClient(secondCertificate).send(
                            HttpRequest.newBuilder(URI.create("https://" + second.dnsName() + ":" + HTTPS_PORT + "/"))
                                    .timeout(Duration.ofSeconds(1))
                                    .GET()
                                    .build(),
                            HttpResponse.BodyHandlers.ofString()));
            assertTrue(hasCause(failure, ConnectException.class), failure.toString());
        });
    }

    @Test
    @Order(Integer.MAX_VALUE)
    void cleanupResources() {
        deleteListener(firstListenerArn);
        deleteListener(secondListenerArn);
        deleteListener(httpListenerArn);
        deleteLoadBalancer(firstLbArn);
        deleteLoadBalancer(secondLbArn);
        deleteLoadBalancer(httpLbArn);
        deleteTargetGroup(firstTargetGroupArn);
    }

    private Certificate requestCertificate(String domainName) {
        return acmService.requestCertificate(
                domainName,
                List.of(),
                ValidationMethod.DNS,
                null,
                KeyAlgorithm.RSA_2048,
                null,
                CertificateOptions.defaultOptions(),
                Map.of("purpose", "elb-tls-test"),
                REGION);
    }

    private static LoadBalancerRef createLoadBalancer(String name) {
        Response response = given()
                .formParam("Action", "CreateLoadBalancer")
                .formParam("Name", name)
                .formParam("Type", "application")
                .header("Authorization", AUTH)
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .extract()
                .response();
        return new LoadBalancerRef(
                response.path("CreateLoadBalancerResponse.CreateLoadBalancerResult.LoadBalancers.member.LoadBalancerArn"),
                response.path("CreateLoadBalancerResponse.CreateLoadBalancerResult.LoadBalancers.member.DNSName"));
    }

    private static String createFixedResponseListener(
            String lbArn, String protocol, int port, String certificateArn, String body) {
        var request = given()
                .formParam("Action", "CreateListener")
                .formParam("LoadBalancerArn", lbArn)
                .formParam("Protocol", protocol)
                .formParam("Port", String.valueOf(port))
                .formParam("DefaultActions.member.1.Type", "fixed-response")
                .formParam("DefaultActions.member.1.FixedResponseConfig.StatusCode", "200")
                .formParam("DefaultActions.member.1.FixedResponseConfig.ContentType", "text/plain")
                .formParam("DefaultActions.member.1.FixedResponseConfig.MessageBody", body)
                .header("Authorization", AUTH);
        if (certificateArn != null) {
            request.formParam("SslPolicy", "ELBSecurityPolicy-TLS13-1-2-2021-06")
                    .formParam("Certificates.member.1.CertificateArn", certificateArn);
        }
        return request
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .extract()
                .path("CreateListenerResponse.CreateListenerResult.Listeners.member.ListenerArn");
    }

    private static String createHealthyTargetGroup() {
        int targetPort = targetServer.getAddress().getPort();
        String targetGroupArn = given()
                .formParam("Action", "CreateTargetGroup")
                .formParam("Name", "https-target")
                .formParam("Protocol", "HTTP")
                .formParam("Port", String.valueOf(targetPort))
                .formParam("VpcId", "vpc-tls-test")
                .formParam("TargetType", "ip")
                .formParam("HealthCheckProtocol", "HTTP")
                .formParam("HealthCheckPath", "/")
                .formParam("HealthCheckIntervalSeconds", "5")
                .formParam("HealthyThresholdCount", "1")
                .header("Authorization", AUTH)
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .extract()
                .path("CreateTargetGroupResponse.CreateTargetGroupResult.TargetGroups.member.TargetGroupArn");

        given()
                .formParam("Action", "RegisterTargets")
                .formParam("TargetGroupArn", targetGroupArn)
                .formParam("Targets.member.1.Id", "127.0.0.1")
                .formParam("Targets.member.1.Port", String.valueOf(targetPort))
                .header("Authorization", AUTH)
            .when()
                .post("/")
            .then()
                .statusCode(200);
        return targetGroupArn;
    }

    private static String createForwardListener(
            String lbArn, int port, String certificateArn, String targetGroupArn) {
        return given()
                .formParam("Action", "CreateListener")
                .formParam("LoadBalancerArn", lbArn)
                .formParam("Protocol", "HTTPS")
                .formParam("Port", String.valueOf(port))
                .formParam("SslPolicy", "ELBSecurityPolicy-TLS13-1-2-2021-06")
                .formParam("Certificates.member.1.CertificateArn", certificateArn)
                .formParam("DefaultActions.member.1.Type", "forward")
                .formParam("DefaultActions.member.1.TargetGroupArn", targetGroupArn)
                .header("Authorization", AUTH)
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .extract()
                .path("CreateListenerResponse.CreateListenerResult.Listeners.member.ListenerArn");
    }

    private static void awaitTargetHealthy(String targetGroupArn) {
        await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(100)).untilAsserted(() ->
                given()
                        .formParam("Action", "DescribeTargetHealth")
                        .formParam("TargetGroupArn", targetGroupArn)
                        .header("Authorization", AUTH)
                    .when()
                        .post("/")
                    .then()
                        .statusCode(200)
                        .body("DescribeTargetHealthResponse.DescribeTargetHealthResult.TargetHealthDescriptions.member.TargetHealth.State",
                                equalTo("healthy")));
    }

    private static void describeHttpsListener(String listenerArn, String certificateArn) {
        given()
                .formParam("Action", "DescribeListeners")
                .formParam("ListenerArns.member.1", listenerArn)
                .header("Authorization", AUTH)
            .when()
                .post("/")
            .then()
                .statusCode(200)
                .body("DescribeListenersResponse.DescribeListenersResult.Listeners.member.Protocol", equalTo("HTTPS"))
                .body("DescribeListenersResponse.DescribeListenersResult.Listeners.member.Port", equalTo(String.valueOf(HTTPS_PORT)))
                .body("DescribeListenersResponse.DescribeListenersResult.Listeners.member.SslPolicy",
                        equalTo("ELBSecurityPolicy-TLS13-1-2-2021-06"))
                .body("DescribeListenersResponse.DescribeListenersResult.Listeners.member.Certificates.member.CertificateArn",
                        equalTo(certificateArn));
    }

    private static HttpsResult awaitHttps(String host, Certificate trustedCertificate) {
        var result = new HttpsResult[1];
        await().atMost(Duration.ofSeconds(10)).pollInterval(Duration.ofMillis(100)).untilAsserted(() -> {
            HttpResponse<String> response = trustedClient(trustedCertificate).send(
                    HttpRequest.newBuilder(URI.create("https://" + host + ":" + HTTPS_PORT + "/"))
                            .timeout(Duration.ofSeconds(2))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            result[0] = new HttpsResult(response.statusCode(), response.body(), response.sslSession().orElseThrow());
        });
        return result[0];
    }

    private static HttpClient trustedClient(Certificate certificate) throws Exception {
        X509Certificate x509 = parseCertificate(certificate.getCertificateBody());
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("acm", x509);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .sslContext(sslContext)
                .build();
    }

    private static void assertPeerCertificate(SSLSession session, Certificate expected, String expectedHost)
            throws Exception {
        X509Certificate actual = assertInstanceOf(X509Certificate.class, session.getPeerCertificates()[0]);
        X509Certificate configured = parseCertificate(expected.getCertificateBody());
        assertEquals(fingerprint(configured), fingerprint(actual));
        assertTrue(actual.getSubjectAlternativeNames().stream()
                .anyMatch(san -> expectedHost.equals(san.get(1))));
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    private static String fingerprint(X509Certificate certificate) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    }

    private static boolean hasCause(Throwable failure, Class<? extends Throwable> type) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (type.isInstance(current)) {
                return true;
            }
        }
        return false;
    }

    private static void deleteListener(String listenerArn) {
        if (listenerArn == null) {
            return;
        }
        given()
                .formParam("Action", "DeleteListener")
                .formParam("ListenerArn", listenerArn)
                .header("Authorization", AUTH)
            .when()
                .post("/");
    }

    private static void deleteLoadBalancer(String lbArn) {
        if (lbArn == null) {
            return;
        }
        given()
                .formParam("Action", "DeleteLoadBalancer")
                .formParam("LoadBalancerArn", lbArn)
                .header("Authorization", AUTH)
            .when()
                .post("/");
    }

    private static void deleteTargetGroup(String targetGroupArn) {
        if (targetGroupArn == null) {
            return;
        }
        given()
                .formParam("Action", "DeleteTargetGroup")
                .formParam("TargetGroupArn", targetGroupArn)
                .header("Authorization", AUTH)
            .when()
                .post("/");
    }

    private record LoadBalancerRef(String arn, String dnsName) {}

    private record HttpsResult(int statusCode, String body, SSLSession session) {}
}
