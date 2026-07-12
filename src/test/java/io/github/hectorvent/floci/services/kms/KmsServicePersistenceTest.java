package io.github.hectorvent.floci.services.kms;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.PersistentStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.services.kms.model.KmsAlias;
import io.github.hectorvent.floci.services.kms.model.KmsGrant;
import io.github.hectorvent.floci.services.kms.model.KmsKey;
import io.github.hectorvent.floci.services.kms.model.KmsKeyManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KmsServicePersistenceTest {

    private static final String REGION = "us-east-1";

    @Test
    void awsManagedAcmKeyAndAliasSurviveRestart(@TempDir Path directory) {
        KmsService first = newService(directory);
        String keyId = first.listAliases(REGION).stream()
                .filter(alias -> "alias/aws/acm".equals(alias.getAliasName()))
                .findFirst()
                .orElseThrow()
                .getTargetKeyId();

        KmsService restarted = newService(directory);
        KmsKey restored = restarted.describeKey("alias/aws/acm", REGION);

        assertEquals(keyId, restored.getKeyId());
        assertEquals(KmsKeyManager.AWS, restored.getKeyManager());
        AwsException error = assertThrows(
                AwsException.class,
                () -> restarted.listResourceTags(restored.getKeyId(), REGION));
        assertEquals("AccessDeniedException", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
    }

    private static KmsService newService(Path directory) {
        return new KmsService(
                load(directory, "kms-keys.json", new TypeReference<Map<String, KmsKey>>() {}),
                load(directory, "kms-aliases.json", new TypeReference<Map<String, KmsAlias>>() {}),
                load(directory, "kms-grants.json", new TypeReference<Map<String, KmsGrant>>() {}),
                new RegionResolver(REGION, "000000000000"));
    }

    private static <V> StorageBackend<String, V> load(
            Path directory, String filename, TypeReference<Map<String, V>> type) {
        PersistentStorage<String, V> storage = new PersistentStorage<>(directory.resolve(filename), type);
        storage.load();
        return storage;
    }
}
