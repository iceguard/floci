package io.github.hectorvent.floci.services.ssm;

import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.interceptor.Interceptor;
import org.jboss.logging.Logger;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@ApplicationScoped
public class SsmCommandLifecycleCoordinator {

    private static final Logger LOG = Logger.getLogger(SsmCommandLifecycleCoordinator.class);

    private final SsmCommandService commandService;
    private ScheduledExecutorService scheduler;

    @Inject
    public SsmCommandLifecycleCoordinator(SsmCommandService commandService) {
        this.commandService = commandService;
    }

    void onStart(@Observes @Priority(Interceptor.Priority.APPLICATION + 1_000) StartupEvent ignored) {
        scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "floci-ssm-command-lifecycle");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleWithFixedDelay(
                this::reconcile, 1, 1, TimeUnit.SECONDS);
    }

    void onStop(@Observes ShutdownEvent ignored) {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        commandService.shutdown();
    }

    private void reconcile() {
        try {
            commandService.restorePersistedLifecycle();
        }
        catch (RuntimeException e) {
            LOG.warn("Unable to reconcile persisted SSM command lifecycle", e);
        }
    }
}
