package io.github.hectorvent.floci.services.autoscaling;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.autoscaling.model.AsgInstance;
import io.github.hectorvent.floci.services.autoscaling.model.InstanceRefresh;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AutoScalingInstanceRefreshPersistenceTest {

    @Test
    void activeRefreshStateSurvivesServiceRestart() {
        SharedStorageFactory storage = new SharedStorageFactory();
        AutoScalingService first = serviceWithStorage(storage);
        first.createAutoScalingGroup("us-east-1", "persisted-asg", null, "lt-source", null, "1", null,
                0, 2, 1, 300, List.of("us-east-1a"), List.of(), List.of(), List.of(), "EC2", 0,
                List.of("Default"), Map.of(), Map.of());
        AsgInstance original = new AsgInstance();
        original.setInstanceId("i-original");
        original.setLifecycleState("InService");
        original.setHealthStatus("Healthy");
        original.setLaunchTemplateId("lt-source");
        original.setLaunchTemplateVersion("1");
        first.describeAutoScalingGroups("us-east-1", List.of("persisted-asg"))
                .getFirst().getInstances().add(original);
        first.saveAutoScalingGroup(first.describeAutoScalingGroups("us-east-1", List.of("persisted-asg")).getFirst());
        InstanceRefresh request = new InstanceRefresh();
        request.setDesiredLaunchTemplateId("lt-refresh");
        request.setDesiredLaunchTemplateVersion("2");
        request.setAutoRollback(true);
        InstanceRefresh started = first.startInstanceRefresh("us-east-1", "persisted-asg", request);
        started.setStatus("RollbackInProgress");
        started.setRollbackReason("forward failure");
        started.setRollbackStartTime(java.time.Instant.parse("2026-07-21T10:00:00Z"));
        started.setPercentageCompleteOnRollback(50);
        started.setInstancesToUpdateOnRollback(1);
        started.getReplacements().getFirst().setRollbackPhase("Launching");
        started.getReplacements().getFirst().setRollbackLaunchClientToken("refresh:rollback:i-original");
        first.saveInstanceRefresh(started);

        AutoScalingService reloaded = serviceWithStorage(storage);
        InstanceRefresh restored = reloaded.activeInstanceRefresh("us-east-1", "persisted-asg").orElseThrow();

        assertEquals(started.getInstanceRefreshId(), restored.getInstanceRefreshId());
        assertEquals(List.of("i-original"), restored.getCandidateInstanceIds());
        assertEquals("i-original", restored.getReplacements().getFirst().getOriginalInstanceId());
        assertEquals("lt-source", restored.getSourceLaunchTemplateId());
        assertEquals("lt-refresh", restored.getDesiredLaunchTemplateId());
        assertEquals("RollbackInProgress", restored.getStatus());
        assertEquals("forward failure", restored.getRollbackReason());
        assertEquals(50, restored.getPercentageCompleteOnRollback());
        assertEquals("Launching", restored.getReplacements().getFirst().getRollbackPhase());
        assertEquals("refresh:rollback:i-original",
                restored.getReplacements().getFirst().getRollbackLaunchClientToken());
        assertEquals("InService", reloaded.describeAutoScalingGroups("us-east-1", List.of("persisted-asg"))
                .getFirst().getInstances().getFirst().getLifecycleState());
    }

    private static AutoScalingService serviceWithStorage(StorageFactory storage) {
        AutoScalingService service = new AutoScalingService();
        service.regionResolver = new RegionResolver("us-east-1", "000000000000");
        service.storageFactory = storage;
        service.initializeStorage();
        return service;
    }

    private static final class SharedStorageFactory extends StorageFactory {
        private final Map<String, StorageBackend<String, ?>> stores = new HashMap<>();

        private SharedStorageFactory() {
            super(null, null);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <V> StorageBackend<String, V> create(String serviceName, String fileName,
                                                    TypeReference<Map<String, V>> typeReference) {
            return (StorageBackend<String, V>) stores.computeIfAbsent(fileName, ignored -> new InMemoryStorage<>());
        }
    }
}
