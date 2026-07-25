package io.github.hectorvent.floci.services.acm;

import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.acm.model.Certificate;
import io.github.hectorvent.floci.services.acm.model.CertificateType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

class AcmServiceTest {

    @Test
    void certificateChainsAreRegionScopedAndDeduplicated() {
        InMemoryStorage<String, Certificate> store = new InMemoryStorage<>();
        store.put("east-one", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-one",
                "east-chain",
                CertificateType.AMAZON_ISSUED));
        store.put("east-two", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-two",
                "east-chain",
                CertificateType.AMAZON_ISSUED));
        store.put("east-empty", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-empty",
                " ",
                CertificateType.AMAZON_ISSUED));
        store.put("east-imported", certificate(
                "arn:aws:acm:us-east-1:000000000000:certificate/east-imported",
                "private-imported-chain",
                CertificateType.IMPORTED));
        store.put("west-one", certificate(
                "arn:aws:acm:us-west-2:000000000000:certificate/west-one",
                "west-chain",
                CertificateType.AMAZON_ISSUED));

        AcmService service = new AcmService(
                store,
                mock(CertificateGenerator.class),
                mock(RegionResolver.class),
                0);

        assertEquals(List.of("east-chain"), service.certificateChains("us-east-1"));
        assertEquals(List.of("west-chain"), service.certificateChains("us-west-2"));
    }

    private static Certificate certificate(String arn, String chain, CertificateType type) {
        Certificate certificate = new Certificate();
        certificate.setArn(arn);
        certificate.setCertificateChain(chain);
        certificate.setType(type);
        certificate.setCertificateBody("leaf-body-must-not-be-exposed");
        certificate.setPrivateKey("private-key-must-not-be-exposed");
        return certificate;
    }
}
