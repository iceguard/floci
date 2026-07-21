package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.PersistentStorage;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IamInstanceProfilePersistenceTest {

    @Test
    void instanceProfileTagsSurviveRestart(@TempDir Path directory) {
        Path profilesFile = directory.resolve("iam-instance-profiles.json");
        IamService first = newService(profilesFile);
        first.createInstanceProfile("profile", "/",
                Map.of("owner", "service", "stage", "initial"));
        first.tagInstanceProfile("profile", Map.of("owner", "platform", "env", "test"));
        first.untagInstanceProfile("profile", java.util.List.of("stage"));

        IamService restarted = newService(profilesFile);
        assertEquals(Map.of("owner", "platform", "env", "test"),
                restarted.listInstanceProfileTags("profile"));
    }

    private static IamService newService(Path profilesFile) {
        PersistentStorage<String, InstanceProfile> profiles = new PersistentStorage<>(
                profilesFile, new TypeReference<Map<String, InstanceProfile>>() {});
        profiles.load();
        return new IamService(
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                profiles,
                new InMemoryStorage<>(),
                new RegionResolver("us-east-1", "000000000000"),
                false);
    }
}
