package io.github.hectorvent.floci.services.acm;

import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.acm.model.Certificate;
import io.github.hectorvent.floci.services.acm.model.CertificateType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class AcmServiceTest {

    @Test
    void certificateChainsAreRegionScopedAndDeduplicated() {
        InMemoryStorage<String, Certificate> store = new InMemoryStorage<>();
        Certificate certificateAuthority = certificate(
                "arn:aws:acm:floci-local:000000000000:certificate-authority/root",
                null,
                null,
                null);
        certificateAuthority.setCertificateBody("local-root");
        store.put("__floci_local_acm_ca__", certificateAuthority);
        store.put("east-one", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-one",
                "east.example.com",
                "east-chain",
                CertificateType.AMAZON_ISSUED));
        store.put("east-two", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-two",
                "east.example.com",
                "east-chain",
                CertificateType.AMAZON_ISSUED));
        store.put("east-empty", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-empty",
                "east.example.com",
                " ",
                CertificateType.AMAZON_ISSUED));
        store.put("east-imported", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-imported",
                "private.example.com",
                "private-imported-chain",
                CertificateType.IMPORTED));
        store.put("east-local-imported", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-local-imported",
                "*.localhost.floci.io",
                "local-imported-chain",
                CertificateType.IMPORTED));
        store.put("west-one", certificate(
                "arn:aws:acm:us-west-2:000000000000:certificate/west-one",
                "west.example.com",
                "west-chain",
                CertificateType.AMAZON_ISSUED));

        AcmService service = new AcmService(
                store,
                mock(CertificateGenerator.class),
                mock(RegionResolver.class),
                0);

        assertEquals(List.of("local-root", "east-chain"), service.certificateChains("us-east-1"));
        assertEquals(List.of("local-root", "west-chain"), service.certificateChains("us-west-2"));
        assertEquals(
                List.of("local-root", "east-chain", "local-imported-chain"),
                service.certificateChains("us-east-1", Optional.of("localhost.floci.io")));
    }

    private static Certificate certificate(String arn, String domainName, String chain, CertificateType type) {
        Certificate certificate = new Certificate();
        certificate.setArn(arn);
        certificate.setDomainName(domainName);
        certificate.setCertificateChain(chain);
        certificate.setType(type);
        certificate.setCertificateBody("leaf-body-must-not-be-exposed");
        certificate.setPrivateKey("private-key-must-not-be-exposed");
        return certificate;
    }
}
