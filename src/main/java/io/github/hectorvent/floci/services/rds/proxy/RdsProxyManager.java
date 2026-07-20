package io.github.hectorvent.floci.services.rds.proxy;

import io.github.hectorvent.floci.services.rds.model.DatabaseEngine;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of all active RDS auth proxies. One proxy per DB instance or cluster.
 */
@ApplicationScoped
public class RdsProxyManager {

    private static final Logger LOG = Logger.getLogger(RdsProxyManager.class);

    private final RdsSigV4Validator sigV4Validator;
    private final ConcurrentHashMap<String, RdsAuthProxy> proxies = new ConcurrentHashMap<>();

    @Inject
    public RdsProxyManager(RdsSigV4Validator sigV4Validator) {
        this.sigV4Validator = sigV4Validator;
    }

    public void startProxy(String instanceId, DatabaseEngine engine, boolean iamEnabled,
                           int proxyPort, String backendHost, int backendPort,
                           String masterUsername, String masterPassword, String dbName,
                           RdsAuthProxy.PasswordValidator passwordValidator) {
        startProxy(instanceId, engine, iamEnabled, proxyPort, backendHost, backendPort,
                masterUsername, masterPassword, dbName, null, null, passwordValidator);
    }

    public void startProxy(String instanceId, DatabaseEngine engine, boolean iamEnabled,
                           int proxyPort, String backendHost, int backendPort,
                           String masterUsername, String masterPassword, String dbName,
                           String dbUserArnPrefix,
                           RdsAuthProxy.PasswordValidator passwordValidator) {
        startProxy(instanceId, engine, iamEnabled, proxyPort, backendHost, backendPort,
                masterUsername, masterPassword, dbName, dbUserArnPrefix, null, passwordValidator);
    }

    public void startProxy(String instanceId, DatabaseEngine engine, boolean iamEnabled,
                           int proxyPort, String backendHost, int backendPort,
                           String masterUsername, String masterPassword, String dbName,
                           String dbUserArnPrefix, String endpointHost,
                           RdsAuthProxy.PasswordValidator passwordValidator) {
        RdsAuthProxy proxy = new RdsAuthProxy(
                instanceId, backendHost, backendPort, engine, iamEnabled,
                masterUsername, masterPassword, dbName, dbUserArnPrefix, endpointHost,
                sigV4Validator, passwordValidator);
        try {
            proxy.start(proxyPort);
            proxies.put(instanceId, proxy);
        } catch (IOException e) {
            throw new RuntimeException("Failed to start RDS proxy for instance " + instanceId
                    + " on port " + proxyPort, e);
        }
    }

    public void stopProxy(String instanceId) {
        RdsAuthProxy proxy = proxies.remove(instanceId);
        if (proxy != null) {
            proxy.stop();
            LOG.infov("Stopped RDS proxy for instance {0}", instanceId);
        }
    }

    public void setIamEnabled(String instanceId, boolean iamEnabled) {
        RdsAuthProxy proxy = proxies.get(instanceId);
        if (proxy != null) {
            proxy.setIamEnabled(iamEnabled);
        }
    }

    public void stopAll() {
        proxies.values().forEach(RdsAuthProxy::stop);
        proxies.clear();
        LOG.info("Stopped all RDS proxies");
    }
}
