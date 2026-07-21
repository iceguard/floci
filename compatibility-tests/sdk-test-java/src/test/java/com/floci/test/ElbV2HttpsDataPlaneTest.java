package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2Client;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.Action;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ActionTypeEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.FixedResponseActionConfig;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancerTypeEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ProtocolEnum;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
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
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;

class ElbV2HttpsDataPlaneTest {

    private static final Logger LOG = Logger.getLogger(ElbV2HttpsDataPlaneTest.class.getName());
    private static final int LISTENER_PORT = 7796;

    private static AcmClient acm;
    private static ElasticLoadBalancingV2Client elb;
    private static String certificateArn;
    private static String loadBalancerArn;
    private static String listenerArn;

    @BeforeAll
    static void setup() {
        acm = TestFixtures.acmClient();
        elb = TestFixtures.elbV2Client();
    }

    @AfterAll
    static void cleanup() {
        try {
            if (listenerArn != null) {
                elb.deleteListener(request -> request.listenerArn(listenerArn));
            }
        } catch (Exception e) {
            LOG.warning("Failed to delete ELBv2 HTTPS listener during cleanup: " + e.getMessage());
        }
        try {
            if (loadBalancerArn != null) {
                elb.deleteLoadBalancer(request -> request.loadBalancerArn(loadBalancerArn));
            }
        } catch (Exception e) {
            LOG.warning("Failed to delete ELBv2 HTTPS load balancer during cleanup: " + e.getMessage());
        }
        try {
            if (certificateArn != null) {
                acm.deleteCertificate(request -> request.certificateArn(certificateArn));
            }
        } catch (Exception e) {
            LOG.warning("Failed to delete ACM certificate during cleanup: " + e.getMessage());
        }
        if (elb != null) {
            elb.close();
        }
        if (acm != null) {
            acm.close();
        }
    }

    @Test
    void officialClientsConfigureAcmBackedHttpsListenerThatTerminatesTls() throws Exception {
        var loadBalancer = elb.createLoadBalancer(request -> request
                        .name(TestFixtures.uniqueName("sdk-https-lb"))
                        .type(LoadBalancerTypeEnum.APPLICATION))
                .loadBalancers().get(0);
        loadBalancerArn = loadBalancer.loadBalancerArn();
        String dnsName = loadBalancer.dnsName();

        certificateArn = acm.requestCertificate(request -> request.domainName(dnsName)).certificateArn();
        String certificatePem = acm.getCertificate(request -> request.certificateArn(certificateArn)).certificate();

        listenerArn = elb.createListener(request -> request
                        .loadBalancerArn(loadBalancerArn)
                        .protocol(ProtocolEnum.HTTPS)
                        .port(LISTENER_PORT)
                        .sslPolicy("ELBSecurityPolicy-TLS13-1-2-2021-06")
                        .certificates(certificate -> certificate.certificateArn(certificateArn))
                        .defaultActions(Action.builder()
                                .type(ActionTypeEnum.FIXED_RESPONSE)
                                .fixedResponseConfig(FixedResponseActionConfig.builder()
                                        .statusCode("200")
                                        .contentType("text/plain")
                                        .messageBody("sdk-tls")
                                        .build())
                                .build()))
                .listeners().get(0).listenerArn();

        var described = elb.describeListeners(request -> request.listenerArns(listenerArn)).listeners().get(0);
        assertThat(described.protocol()).isEqualTo(ProtocolEnum.HTTPS);
        assertThat(described.port()).isEqualTo(LISTENER_PORT);
        assertThat(described.sslPolicy()).isEqualTo("ELBSecurityPolicy-TLS13-1-2-2021-06");
        assertThat(described.certificates()).extracting(certificate -> certificate.certificateArn())
                .containsExactly(certificateArn);

        X509Certificate expected = parseCertificate(certificatePem);
        HttpClient client = trustedClient(expected);
        HttpResponse<String> result = awaitHttps(client, dnsName);

        assertThat(result.statusCode()).isEqualTo(200);
        assertThat(result.body()).isEqualTo("sdk-tls");
        X509Certificate actual = (X509Certificate) result.sslSession().orElseThrow().getPeerCertificates()[0];
        assertThat(fingerprint(actual)).isEqualTo(fingerprint(expected));
        assertThat(actual.getSubjectAlternativeNames())
                .anySatisfy(san -> assertThat(san.get(1)).isEqualTo(dnsName));
    }

    private static HttpClient trustedClient(X509Certificate certificate) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("acm", certificate);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .sslContext(sslContext)
                .build();
    }

    private static HttpResponse<String> awaitHttps(HttpClient client, String dnsName) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        Exception lastFailure = null;
        do {
            try {
                return client.send(
                        HttpRequest.newBuilder(URI.create("https://" + dnsName + ":" + LISTENER_PORT + "/"))
                                .timeout(Duration.ofSeconds(2))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                lastFailure = e;
                Thread.sleep(100);
            }
        } while (System.nanoTime() < deadline);
        throw lastFailure;
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }

    private static String fingerprint(X509Certificate certificate) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    }
}
