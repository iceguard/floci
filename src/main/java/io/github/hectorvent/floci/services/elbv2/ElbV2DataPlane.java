package io.github.hectorvent.floci.services.elbv2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.acm.AcmService;
import io.github.hectorvent.floci.services.acm.model.Certificate;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.elbv2.model.Action;
import io.github.hectorvent.floci.services.elbv2.model.Listener;
import io.github.hectorvent.floci.services.elbv2.model.LoadBalancer;
import io.github.hectorvent.floci.services.elbv2.model.Rule;
import io.github.hectorvent.floci.services.elbv2.model.RuleCondition;
import io.github.hectorvent.floci.services.elbv2.model.TargetDescription;
import io.github.hectorvent.floci.services.elbv2.model.TargetGroup;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.lambda.model.InvocationType;
import io.github.hectorvent.floci.services.lambda.model.InvokeResult;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.SSLOptions;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@ApplicationScoped
public class ElbV2DataPlane {

    private static final Logger LOG = Logger.getLogger(ElbV2DataPlane.class);

    private static final List<String> HOP_BY_HOP_HEADERS = List.of(
            "connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailers", "proxy-authorization", "proxy-authenticate"
    );

    @Inject
    Vertx vertx;

    @Inject
    ElbV2Service elbV2Service;

    @Inject
    ElbV2HealthChecker healthChecker;

    @Inject
    EmulatorConfig config;

    @Inject
    LambdaService lambdaService;

    @Inject
    Ec2Service ec2Service;

    @Inject
    AcmService acmService;

    @Inject
    ObjectMapper objectMapper;

    private final Map<Integer, HttpServer> servers = new ConcurrentHashMap<>();
    private final Map<Integer, Map<String, String>> listenersByHostAndPort = new ConcurrentHashMap<>();
    private final Map<String, ListenerBinding> listenerBindings = new ConcurrentHashMap<>();
    private final Map<String, AtomicReference<List<CompiledRule>>> ruleChains = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> rrCounters = new ConcurrentHashMap<>();
    private final Map<String, String> listenerRegions = new ConcurrentHashMap<>();

    private HttpClient proxyClient;

    private record ListenerBinding(int port, boolean secure, Set<String> hosts, List<String> certificateArns) {}

    @PostConstruct
    void init() {
        proxyClient = vertx.createHttpClient(new HttpClientOptions()
                .setMaxPoolSize(100)
                .setConnectTimeout(5000)
                .setKeepAlive(true));
    }

    @PreDestroy
    void shutdown() {
        for (Map.Entry<Integer, HttpServer> e : servers.entrySet()) {
            e.getValue().close();
        }
        servers.clear();
        listenersByHostAndPort.clear();
        listenerBindings.clear();
        ruleChains.clear();
        rrCounters.clear();
        listenerRegions.clear();
    }

    public void startListener(Listener listener, String region, List<Rule> rules) {
        if (config.services().elbv2().mock()) {
            return;
        }
        String listenerArn = listener.getListenerArn();
        List<CompiledRule> compiled = compileRules(rules);
        ruleChains.put(listenerArn, new AtomicReference<>(compiled));
        listenerRegions.put(listenerArn, region);
        ListenerBinding binding = binding(listener, region);
        requireCompatiblePort(binding, listenerArn);
        listenerBindings.put(listenerArn, binding);
        addHostBindings(listenerArn, binding);
        HttpServer server = servers.get(binding.port());
        if (server == null) {
            servers.computeIfAbsent(binding.port(), this::startPortServer);
        } else if (binding.secure()) {
            refreshTlsOptions(binding.port(), server);
        }
    }

    public void restartListener(Listener listener, String region, List<Rule> rules) {
        if (config.services().elbv2().mock()) {
            return;
        }
        String listenerArn = listener.getListenerArn();
        ListenerBinding newBinding = binding(listener, region);
        ListenerBinding oldBinding = listenerBindings.get(listenerArn);
        if (newBinding.equals(oldBinding)) {
            ruleChains.put(listenerArn, new AtomicReference<>(compileRules(rules)));
            listenerRegions.put(listenerArn, region);
            addHostBindings(listenerArn, newBinding);
            servers.computeIfAbsent(newBinding.port(), this::startPortServer);
            return;
        }
        requireCompatiblePort(newBinding, listenerArn);
        if (oldBinding != null && oldBinding.port() == newBinding.port()
                && oldBinding.secure() == newBinding.secure()) {
            removeHostBindings(listenerArn, oldBinding);
            listenerBindings.put(listenerArn, newBinding);
            ruleChains.put(listenerArn, new AtomicReference<>(compileRules(rules)));
            listenerRegions.put(listenerArn, region);
            addHostBindings(listenerArn, newBinding);
            HttpServer server = servers.get(newBinding.port());
            if (newBinding.secure() && server != null) {
                refreshTlsOptions(newBinding.port(), server);
            }
            return;
        }
        if (oldBinding != null && oldBinding.port() == newBinding.port()) {
            removeHostBindings(listenerArn, oldBinding);
            listenerBindings.put(listenerArn, newBinding);
            ruleChains.put(listenerArn, new AtomicReference<>(compileRules(rules)));
            listenerRegions.put(listenerArn, region);
            addHostBindings(listenerArn, newBinding);
            restartPortServer(newBinding.port());
            return;
        }
        oldBinding = listenerBindings.remove(listenerArn);
        if (oldBinding != null) {
            removeHostBindings(listenerArn, oldBinding);
            closePortServerIfUnused(oldBinding.port(), listenersByHostAndPort.get(oldBinding.port()));
        }
        startListener(listener, region, rules);
    }

    public void stopListener(String listenerArn) {
        ListenerBinding binding = listenerBindings.remove(listenerArn);
        if (binding != null) {
            removeHostBindings(listenerArn, binding);
            Map<String, String> listenersByHost = listenersByHostAndPort.get(binding.port());
            if (listenersByHost == null || listenersByHost.isEmpty()) {
                closePortServerIfUnused(binding.port(), listenersByHost);
            } else if (binding.secure()) {
                HttpServer server = servers.get(binding.port());
                if (server != null) {
                    refreshTlsOptions(binding.port(), server);
                }
            }
        }
        ruleChains.remove(listenerArn);
        listenerRegions.remove(listenerArn);
    }

    public void recompileRules(String listenerArn, List<Rule> rules) {
        AtomicReference<List<CompiledRule>> ref = ruleChains.get(listenerArn);
        if (ref != null) {
            ref.set(compileRules(rules));
        }
    }

    private HttpServer startPortServer(int port) {
        boolean secure = portIsSecure(port);
        HttpServerOptions options = new HttpServerOptions()
                .setHost("0.0.0.0")
                .setPort(port);
        if (secure) {
            options.setSsl(true)
                    .setSni(true)
                    .setPemKeyCertOptions(tlsKeyCertOptions(port));
        }
        HttpServer server = vertx.createHttpServer(options);
        server.requestHandler(req -> handleRequest(req, port));
        server.listen()
                .onSuccess(s -> LOG.infov("ELBv2 {0} listener port started on {1}",
                        secure ? "HTTPS" : "HTTP", String.valueOf(port)))
                .onFailure(err -> {
                    servers.remove(port, server);
                    clearPortBindings(port);
                    server.close();
                    LOG.warnv("ELBv2 listener port failed to start on {0}: {1}", String.valueOf(port), err.getMessage());
                });
        return server;
    }

    private void closePortServerIfUnused(int port, Map<String, String> listenersByHost) {
        if (listenersByHost != null && !listenersByHost.isEmpty()) {
            return;
        }
        if (listenersByHost != null) {
            listenersByHostAndPort.remove(port, listenersByHost);
        }
        HttpServer server = servers.remove(port);
        if (server != null) {
            server.close();
        }
    }

    private void clearPortBindings(int port) {
        Map<String, String> listenersByHost = listenersByHostAndPort.remove(port);
        if (listenersByHost == null) {
            return;
        }
        for (String listenerArn : listenersByHost.values()) {
            listenerBindings.remove(listenerArn);
            ruleChains.remove(listenerArn);
            listenerRegions.remove(listenerArn);
        }
    }

    private ListenerBinding binding(Listener listener, String region) {
        LoadBalancer loadBalancer = elbV2Service.getLoadBalancer(region, listener.getLoadBalancerArn());
        String host = loadBalancer != null ? normalizeHost(loadBalancer.getDnsName()) : listener.getLoadBalancerArn();
        boolean secure = "HTTPS".equalsIgnoreCase(listener.getProtocol());
        Set<String> hosts = new LinkedHashSet<>();
        hosts.add(host);
        List<String> certificateArns = List.copyOf(listener.getCertificates());
        if (secure) {
            for (String certificateArn : certificateArns) {
                Certificate certificate = acmService.getCertificate(certificateArn, region);
                addCertificateHosts(hosts, certificate);
            }
        }
        return new ListenerBinding(listener.getPort(), secure, Set.copyOf(hosts), certificateArns);
    }

    private void requireCompatiblePort(ListenerBinding binding, String listenerArn) {
        for (Map.Entry<String, ListenerBinding> entry : listenerBindings.entrySet()) {
            ListenerBinding existing = entry.getValue();
            if (!entry.getKey().equals(listenerArn)
                    && existing.port() == binding.port()
                    && existing.secure() != binding.secure()) {
                throw new IllegalStateException("ELBv2 listeners sharing port " + binding.port()
                        + " must use the same front-end protocol");
            }
        }
    }

    private void addHostBindings(String listenerArn, ListenerBinding binding) {
        Map<String, String> listenersByHost = listenersByHostAndPort.computeIfAbsent(
                binding.port(), ignored -> new ConcurrentHashMap<>());
        for (String host : binding.hosts()) {
            listenersByHost.put(host, listenerArn);
        }
    }

    private void removeHostBindings(String listenerArn, ListenerBinding binding) {
        Map<String, String> listenersByHost = listenersByHostAndPort.get(binding.port());
        if (listenersByHost == null) {
            return;
        }
        for (String host : binding.hosts()) {
            listenersByHost.remove(host, listenerArn);
        }
    }

    private void refreshTlsOptions(int port, HttpServer server) {
        server.updateSSLOptions(new SSLOptions().setKeyCertOptions(tlsKeyCertOptions(port)), true)
                .onFailure(err -> LOG.warnv("ELBv2 listener TLS certificates failed to refresh on {0}: {1}",
                        String.valueOf(port), err.getMessage()));
    }

    private void restartPortServer(int port) {
        HttpServer server = servers.remove(port);
        if (server == null) {
            servers.computeIfAbsent(port, this::startPortServer);
            return;
        }
        server.close().onComplete(ignored -> {
            if (listenersByHostAndPort.containsKey(port)) {
                servers.computeIfAbsent(port, this::startPortServer);
            }
        });
    }

    private PemKeyCertOptions tlsKeyCertOptions(int port) {
        Map<String, Certificate> certificates = new LinkedHashMap<>();
        for (Map.Entry<String, ListenerBinding> entry : listenerBindings.entrySet()) {
            ListenerBinding binding = entry.getValue();
            if (binding.port() != port || !binding.secure()) {
                continue;
            }
            String region = listenerRegions.get(entry.getKey());
            for (String certificateArn : binding.certificateArns()) {
                certificates.computeIfAbsent(certificateArn, arn -> acmService.getCertificate(arn, region));
            }
        }
        if (certificates.isEmpty()) {
            throw new IllegalStateException("HTTPS listener port " + port + " has no ACM certificate");
        }
        PemKeyCertOptions options = new PemKeyCertOptions();
        for (Certificate certificate : certificates.values()) {
            if (certificate.getPrivateKey() == null || certificate.getPrivateKey().isBlank()
                    || certificate.getCertificateBody() == null || certificate.getCertificateBody().isBlank()) {
                throw new IllegalStateException("ACM certificate " + certificate.getArn()
                        + " does not contain TLS key material");
            }
            options.addKeyValue(Buffer.buffer(certificate.getPrivateKey()));
            options.addCertValue(Buffer.buffer(certificatePemChain(certificate)));
        }
        return options;
    }

    private boolean portIsSecure(int port) {
        return listenerBindings.values().stream()
                .filter(binding -> binding.port() == port)
                .findFirst()
                .map(ListenerBinding::secure)
                .orElse(false);
    }

    private static String certificatePemChain(Certificate certificate) {
        String body = certificate.getCertificateBody().stripTrailing();
        String chain = certificate.getCertificateChain();
        if (chain == null || chain.isBlank()) {
            return body + "\n";
        }
        try {
            CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(chain.getBytes(StandardCharsets.US_ASCII)));
            return body + "\n" + chain.strip() + "\n";
        } catch (CertificateException e) {
            LOG.warnv("ACM certificate {0} has an invalid optional chain; serving its leaf certificate only",
                    certificate.getArn());
            return body + "\n";
        }
    }

    private static void addCertificateHosts(Set<String> hosts, Certificate certificate) {
        if (certificate.getDomainName() != null && !certificate.getDomainName().isBlank()) {
            hosts.add(normalizeHost(certificate.getDomainName()));
        }
        if (certificate.getSubjectAlternativeNames() != null) {
            for (String san : certificate.getSubjectAlternativeNames()) {
                if (san != null && !san.isBlank()) {
                    hosts.add(normalizeHost(san));
                }
            }
        }
    }

    private void handleRequest(io.vertx.core.http.HttpServerRequest req, int port) {
        String listenerArn = resolveListenerArn(port, req.host());
        if (listenerArn == null) {
            req.response().setStatusCode(502).end("No listener for host");
            return;
        }
        String region = listenerRegions.get(listenerArn);
        if (region == null) {
            req.response().setStatusCode(502).end("No listener region");
            return;
        }
        AtomicReference<List<CompiledRule>> ref = ruleChains.get(listenerArn);
        if (ref == null) {
            req.response().setStatusCode(502).end("No rule chain");
            return;
        }
        List<CompiledRule> chain = ref.get();
        for (CompiledRule compiled : chain) {
            if (compiled.matches(req)) {
                executeAction(req, compiled.action, region);
                return;
            }
        }
        req.response().setStatusCode(502).end("No matching rule");
    }

    private String resolveListenerArn(int port, String hostHeader) {
        Map<String, String> listenersByHost = listenersByHostAndPort.get(port);
        if (listenersByHost == null || listenersByHost.isEmpty()) {
            return null;
        }
        String host = normalizeHost(hostHeader);
        String listenerArn = listenersByHost.get(host);
        if (listenerArn != null) {
            return listenerArn;
        }
        Set<String> wildcardMatches = listenersByHost.entrySet().stream()
                .filter(entry -> wildcardMatches(entry.getKey(), host))
                .map(Map.Entry::getValue)
                .collect(Collectors.toSet());
        if (wildcardMatches.size() == 1) {
            return wildcardMatches.iterator().next();
        }
        Set<String> listenerArns = new LinkedHashSet<>(listenersByHost.values());
        if (listenerArns.size() == 1) {
            return listenerArns.iterator().next();
        }
        return null;
    }

    private static boolean wildcardMatches(String candidate, String host) {
        return candidate.startsWith("*.")
                && host.length() > candidate.length() - 1
                && host.endsWith(candidate.substring(1))
                && host.indexOf('.') == host.length() - candidate.length() + 1;
    }

    private static String normalizeHost(String host) {
        if (host == null) {
            return "";
        }
        String normalized = host.trim().toLowerCase();
        int colon = normalized.lastIndexOf(':');
        int bracket = normalized.lastIndexOf(']');
        if (colon > -1 && colon > bracket) {
            normalized = normalized.substring(0, colon);
        }
        return normalized;
    }

    private void executeAction(io.vertx.core.http.HttpServerRequest req, Action action, String region) {
        if (action == null) {
            req.response().setStatusCode(502).end("No action");
            return;
        }
        switch (action.getType() != null ? action.getType() : "") {
            case "forward" -> executeForward(req, action, region);
            case "redirect" -> executeRedirect(req, action);
            case "fixed-response" -> executeFixedResponse(req, action);
            default -> req.response().setStatusCode(502).end("Unsupported action type");
        }
    }

    private void executeForward(io.vertx.core.http.HttpServerRequest req, Action action, String region) {
        String tgArn = resolveTgArn(action);
        if (tgArn == null) {
            req.response().setStatusCode(502).end("No target group");
            return;
        }
        TargetGroup tg = elbV2Service.getTargetGroup(region, tgArn);
        if (tg == null) {
            req.response().setStatusCode(502).end("Target group not found");
            return;
        }

        if ("lambda".equals(tg.getTargetType())) {
            List<TargetDescription> targets = tg.getTargets();
            if (targets.isEmpty()) {
                req.response().setStatusCode(503).end("No Lambda targets registered");
                return;
            }
            String functionArn = targets.get(0).getId();
            invokeLambdaTarget(req, functionArn, region);
            return;
        }

        List<TargetDescription> allTargets = tg.getTargets();
        List<TargetDescription> healthy = allTargets.stream()
                .filter(t -> healthChecker.isHealthy(tgArn, t, ElbV2HealthChecker.effectivePort(t, tg)))
                .collect(Collectors.toList());
        List<TargetDescription> candidates = healthy.isEmpty() ? allTargets : healthy;
        if (candidates.isEmpty()) {
            req.response().setStatusCode(503).end("No targets available");
            return;
        }
        AtomicInteger counter = rrCounters.computeIfAbsent(tgArn, k -> new AtomicInteger(0));
        int idx = Math.abs(counter.getAndIncrement() % candidates.size());
        TargetDescription target = candidates.get(idx);
        int targetPort = ElbV2HealthChecker.effectivePort(target, tg);
        proxyRequest(req, ElbV2TargetResolver.resolveHost(ec2Service, tg, target), targetPort);
    }

    private void invokeLambdaTarget(io.vertx.core.http.HttpServerRequest req, String functionArn, String region) {
        req.bodyHandler(body -> {
            Map<String, Object> event = buildAlbEvent(req, body);
            // Lambda invocation is synchronous and may take seconds while a cold container
            // boots and polls the Runtime API. The Runtime API itself runs on Vert.x event
            // loops, so blocking the listener's event loop here would deadlock the runtime
            // and the function would time out. Offload to a worker thread, same as WebSocket.
            // ordered=false so independent ALB requests run in parallel on the worker pool.
            vertx.<InvokeResult>executeBlocking(() -> {
                byte[] payload = objectMapper.writeValueAsBytes(event);
                return lambdaService.invoke(region, functionArn, payload, InvocationType.RequestResponse);
            }, false).onSuccess(result -> {
                try {
                    writeLambdaResponse(req, result);
                } catch (Exception e) {
                    LOG.errorf(e, "Error writing Lambda response for %s", functionArn);
                    req.response().setStatusCode(502).end("Lambda invocation error");
                }
            }).onFailure(e -> {
                LOG.errorf(e, "Error invoking Lambda target %s", functionArn);
                req.response().setStatusCode(502).end("Lambda invocation error");
            });
        });
    }

    private void writeLambdaResponse(io.vertx.core.http.HttpServerRequest req, InvokeResult result) throws java.io.IOException {
        if (result.getFunctionError() != null) {
            req.response().setStatusCode(502).end("Lambda function error: " + result.getFunctionError());
            return;
        }

        if (result.getPayload() == null || result.getPayload().length == 0) {
            req.response().setStatusCode(200).end();
            return;
        }

        Map<String, Object> lambdaResp = objectMapper.readValue(result.getPayload(),
                new TypeReference<Map<String, Object>>() {});

        int statusCode = 200;
        Object sc = lambdaResp.get("statusCode");
        if (sc != null) {
            statusCode = ((Number) sc).intValue();
        }

        req.response().setStatusCode(statusCode);

        Object headers = lambdaResp.get("headers");
        if (headers instanceof Map<?, ?> headerMap) {
            for (Map.Entry<?, ?> entry : headerMap.entrySet()) {
                req.response().putHeader(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
            }
        }

        Object multiValueHeaders = lambdaResp.get("multiValueHeaders");
        if (multiValueHeaders instanceof Map<?, ?> mvh) {
            for (Map.Entry<?, ?> entry : mvh.entrySet()) {
                if (entry.getValue() instanceof List<?> values) {
                    for (Object v : values) {
                        req.response().putHeader(String.valueOf(entry.getKey()), String.valueOf(v));
                    }
                }
            }
        }

        Object responseBody = lambdaResp.get("body");
        Boolean isBase64 = (Boolean) lambdaResp.get("isBase64Encoded");
        if (responseBody == null) {
            req.response().end();
        } else if (Boolean.TRUE.equals(isBase64)) {
            byte[] decoded = Base64.getDecoder().decode(String.valueOf(responseBody));
            req.response().end(Buffer.buffer(decoded));
        } else {
            req.response().end(String.valueOf(responseBody));
        }
    }

    private Map<String, Object> buildAlbEvent(io.vertx.core.http.HttpServerRequest req, Buffer body) {
        Map<String, Object> event = new HashMap<>();
        event.put("requestContext", Map.of("elb", Map.of("targetGroupArn", "")));
        event.put("httpMethod", req.method().name());
        event.put("path", req.path() != null ? req.path() : "/");

        Map<String, String> queryParams = new HashMap<>();
        Map<String, List<String>> multiValueQueryParams = new HashMap<>();
        String query = req.query();
        if (query != null && !query.isEmpty()) {
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                String key = eq >= 0 ? pair.substring(0, eq) : pair;
                String val = eq >= 0 ? pair.substring(eq + 1) : "";
                queryParams.putIfAbsent(key, val);
                multiValueQueryParams.computeIfAbsent(key, k -> new ArrayList<>()).add(val);
            }
        }
        event.put("queryStringParameters", queryParams.isEmpty() ? null : queryParams);
        event.put("multiValueQueryStringParameters", multiValueQueryParams.isEmpty() ? null : multiValueQueryParams);

        Map<String, String> headers = new HashMap<>();
        Map<String, List<String>> multiValueHeaders = new HashMap<>();
        req.headers().forEach(entry -> {
            String key = entry.getKey().toLowerCase();
            headers.putIfAbsent(key, entry.getValue());
            multiValueHeaders.computeIfAbsent(key, k -> new ArrayList<>()).add(entry.getValue());
        });
        event.put("headers", headers);
        event.put("multiValueHeaders", multiValueHeaders);

        boolean isBase64 = false;
        String bodyStr = null;
        if (body != null && body.length() > 0) {
            String contentType = req.getHeader("Content-Type");
            if (contentType != null && !contentType.startsWith("text/") && !contentType.contains("json")
                    && !contentType.contains("xml") && !contentType.contains("form")) {
                bodyStr = Base64.getEncoder().encodeToString(body.getBytes());
                isBase64 = true;
            } else {
                bodyStr = body.toString(StandardCharsets.UTF_8);
            }
        }
        event.put("body", bodyStr);
        event.put("isBase64Encoded", isBase64);

        return event;
    }

    private String resolveTgArn(Action action) {
        if (action.getTargetGroupArn() != null) {
            return action.getTargetGroupArn();
        }
        List<Action.TargetGroupTuple> tuples = action.getTargetGroups();
        if (tuples == null || tuples.isEmpty()) {
            return null;
        }
        double total = tuples.stream().mapToDouble(t -> t.getWeight() != null ? t.getWeight() : 1).sum();
        double roll = Math.random() * total;
        double cumulative = 0;
        for (Action.TargetGroupTuple tuple : tuples) {
            cumulative += (tuple.getWeight() != null ? tuple.getWeight() : 1);
            if (roll < cumulative) {
                return tuple.getTargetGroupArn();
            }
        }
        return tuples.get(tuples.size() - 1).getTargetGroupArn();
    }

    private void proxyRequest(io.vertx.core.http.HttpServerRequest req, String host, int port) {
        req.bodyHandler(body -> {
            RequestOptions opts = new RequestOptions()
                    .setHost(host)
                    .setPort(port)
                    .setURI(req.uri())
                    .setMethod(req.method());
            proxyClient.request(opts)
                    .onSuccess(clientReq -> {
                        req.headers().forEach(entry -> {
                            if (!HOP_BY_HOP_HEADERS.contains(entry.getKey().toLowerCase())) {
                                clientReq.putHeader(entry.getKey(), entry.getValue());
                            }
                        });
                        clientReq.putHeader("Host", host + ":" + port);
                        clientReq.send(body)
                                .onSuccess(resp -> {
                                    req.response().setStatusCode(resp.statusCode());
                                    resp.headers().forEach(entry -> {
                                        if (!HOP_BY_HOP_HEADERS.contains(entry.getKey().toLowerCase())) {
                                            req.response().putHeader(entry.getKey(), entry.getValue());
                                        }
                                    });
                                    resp.body()
                                            .onSuccess(req.response()::end)
                                            .onFailure(err -> req.response().setStatusCode(502).end("Body error"));
                                })
                                .onFailure(err -> req.response().setStatusCode(502).end("Bad gateway"));
                    })
                    .onFailure(err -> req.response().setStatusCode(503).end("Service unavailable"));
        });
    }

    private void executeRedirect(io.vertx.core.http.HttpServerRequest req, Action action) {
        String reqHost = req.host();
        String reqPort = "";
        if (reqHost != null && reqHost.contains(":")) {
            String[] parts = reqHost.split(":", 2);
            reqHost = parts[0];
            reqPort = parts[1];
        }
        String reqPath = req.path() != null ? req.path() : "/";
        String reqQuery = req.query();
        String reqProtocol = "HTTP";

        String protocol = action.getRedirectProtocol() != null ? action.getRedirectProtocol() : reqProtocol;
        String host = action.getRedirectHost() != null ? action.getRedirectHost() : reqHost;
        String portStr = action.getRedirectPort() != null ? action.getRedirectPort() : reqPort;
        String path = action.getRedirectPath() != null ? action.getRedirectPath() : reqPath;
        String query = action.getRedirectQuery() != null ? action.getRedirectQuery() : (reqQuery != null ? reqQuery : "");

        final String finalReqHost = reqHost;
        final String finalReqPort = reqPort;

        protocol = substitute(protocol, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);
        host = substitute(host, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);
        portStr = substitute(portStr, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);
        path = substitute(path, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);
        query = substitute(query, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);

        StringBuilder location = new StringBuilder(protocol.toLowerCase()).append("://").append(host);
        if (!portStr.isEmpty()) {
            location.append(":").append(portStr);
        }
        location.append(path);
        if (!query.isEmpty()) {
            location.append("?").append(query);
        }

        int statusCode = "HTTP_301".equals(action.getRedirectStatusCode()) ? 301 : 302;
        req.response()
                .setStatusCode(statusCode)
                .putHeader("Location", location.toString())
                .end();
    }

    private String substitute(String template, String host, String port, String path, String protocol, String query) {
        if (template == null) {
            return "";
        }
        String result = template
                .replace("#{host}", host != null ? host : "")
                .replace("#{port}", port != null ? port : "")
                .replace("#{path}", path != null ? path : "/")
                .replace("#{protocol}", protocol != null ? protocol : "HTTP");
        if (query != null && !query.isEmpty()) {
            result = result.replace("#{query}", query);
        } else {
            result = result.replace("#{query}", "");
        }
        return result;
    }

    private void executeFixedResponse(io.vertx.core.http.HttpServerRequest req, Action action) {
        int statusCode = 200;
        try {
            if (action.getFixedResponseStatusCode() != null) {
                statusCode = Integer.parseInt(action.getFixedResponseStatusCode());
            }
        } catch (NumberFormatException ignored) {
        }
        req.response().setStatusCode(statusCode);
        if (action.getFixedResponseContentType() != null) {
            req.response().putHeader("Content-Type", action.getFixedResponseContentType());
        }
        String body = action.getFixedResponseMessageBody() != null ? action.getFixedResponseMessageBody() : "";
        req.response().end(body);
    }

    private List<CompiledRule> compileRules(List<Rule> rules) {
        return rules.stream()
                .map(CompiledRule::new)
                .collect(Collectors.toList());
    }

    private Action getRoutingAction(Rule rule) {
        List<Action> actions = rule.getActions();
        if (actions == null || actions.isEmpty()) {
            return null;
        }
        Action last = null;
        for (Action a : actions) {
            String type = a.getType();
            if ("forward".equals(type) || "redirect".equals(type) || "fixed-response".equals(type)) {
                last = a;
            }
        }
        return last;
    }

    private static boolean globMatches(String pattern, String text) {
        if (text == null) {
            return false;
        }
        StringBuilder regex = new StringBuilder("(?i)");
        for (char c : pattern.toCharArray()) {
            if (c == '*') {
                regex.append(".*");
            } else if (c == '?') {
                regex.append('.');
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.matches(regex.toString(), text);
    }

    private class CompiledRule {
        final Rule rule;
        final Action action;

        CompiledRule(Rule rule) {
            this.rule = rule;
            this.action = getRoutingAction(rule);
        }

        boolean matches(io.vertx.core.http.HttpServerRequest req) {
            if (rule.isDefault()) {
                return true;
            }
            for (RuleCondition condition : rule.getConditions()) {
                if (!matchesCondition(condition, req)) {
                    return false;
                }
            }
            return true;
        }

        private boolean matchesCondition(RuleCondition condition, io.vertx.core.http.HttpServerRequest req) {
            String field = condition.getField();
            if (field == null) {
                return true;
            }
            return switch (field) {
                case "host-header" -> {
                    List<String> patterns = condition.getHostHeaderValues().isEmpty()
                            ? condition.getValues()
                            : condition.getHostHeaderValues();
                    String host = req.host();
                    if (host != null && host.contains(":")) {
                        host = host.substring(0, host.indexOf(':'));
                    }
                    String effectiveHost = host;
                    yield patterns.stream().anyMatch(p -> globMatches(p, effectiveHost));
                }
                case "path-pattern" -> {
                    List<String> patterns = condition.getPathPatternValues().isEmpty()
                            ? condition.getValues()
                            : condition.getPathPatternValues();
                    String path = req.path();
                    yield patterns.stream().anyMatch(p -> globMatches(p, path));
                }
                case "http-header" -> {
                    String headerName = condition.getHttpHeaderName();
                    if (headerName == null) {
                        yield true;
                    }
                    String headerValue = req.getHeader(headerName);
                    yield condition.getHttpHeaderValues().stream().anyMatch(p -> globMatches(p, headerValue));
                }
                case "http-request-method" -> {
                    String method = req.method().name();
                    yield condition.getHttpMethodValues().stream()
                            .anyMatch(m -> m.equalsIgnoreCase(method));
                }
                case "query-string" -> {
                    String queryString = req.query();
                    Map<String, String> queryParams = parseQueryString(queryString);
                    yield condition.getQueryStringValues().stream().allMatch(pair -> {
                        String key = pair.getKey();
                        String valuePattern = pair.getValue();
                        if (key == null) {
                            return queryParams.values().stream().anyMatch(v -> globMatches(valuePattern, v));
                        }
                        String paramValue = queryParams.get(key);
                        return paramValue != null && globMatches(valuePattern, paramValue);
                    });
                }
                case "source-ip" -> true;
                default -> true;
            };
        }

        private Map<String, String> parseQueryString(String query) {
            Map<String, String> params = new java.util.LinkedHashMap<>();
            if (query == null || query.isEmpty()) {
                return params;
            }
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                if (eq >= 0) {
                    params.put(pair.substring(0, eq), pair.substring(eq + 1));
                } else {
                    params.put(pair, "");
                }
            }
            return params;
        }
    }
}
