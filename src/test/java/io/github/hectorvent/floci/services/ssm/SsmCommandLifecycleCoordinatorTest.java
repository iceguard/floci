package io.github.hectorvent.floci.services.ssm;

import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class SsmCommandLifecycleCoordinatorTest {

    @Test
    void applicationShutdownStopsDirectExecutionWorkers() {
        SsmCommandService commandService = mock(SsmCommandService.class);
        SsmCommandLifecycleCoordinator coordinator = new SsmCommandLifecycleCoordinator(commandService);

        coordinator.onStop(null);

        verify(commandService).shutdown();
    }
}
