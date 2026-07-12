package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.InstanceNetworkInterface;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IMDS-compatible HTTP server bound to port 9169 on the Floci host.
 * EC2 containers are launched with AWS_EC2_METADATA_SERVICE_ENDPOINT pointing here.
 *
 * Implements IMDSv2 (token-based) and IMDSv1 (no token) — containers using the
 * standard AWS SDK credential chain will hit /latest/meta-data/iam/security-credentials/
 * to obtain temporary credentials backed by the instance's IAM instance profile.
 */
@ApplicationScoped
public class Ec2MetadataServer {

    private static final Logger LOG = Logger.getLogger(Ec2MetadataServer.class);
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);
    private static final String INSTANCE_TAGS_PREFIX = "/latest/meta-data/tags/instance/";
    private static final Duration CREDENTIAL_LIFETIME = Duration.ofHours(1);
    private static final Duration CREDENTIAL_ROTATION_WINDOW = Duration.ofMinutes(5);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String METADATA_VERSION_PATTERN = "/[0-9]{4}-[0-9]{2}-[0-9]{2}/.*";

    private final Vertx vertx;
    private final EmulatorConfig config;
    private final IamService iamService;

    /** IMDSv2: token value → Instance */
    private final Map<String, Instance> tokenToInstance = new ConcurrentHashMap<>();
    /** IMDSv1 fallback: container bridge IP → Instance */
    private final Map<String, Instance> containerIpToInstance = new ConcurrentHashMap<>();
    /** Instance ID → current credential plus every still-overlapping issued credential. */
    private final Map<String, InstanceCredentialState> instanceCredentials = new ConcurrentHashMap<>();

    private volatile HttpServer httpServer;

    @Inject
    public Ec2MetadataServer(Vertx vertx, EmulatorConfig config, IamService iamService) {
        this.vertx = vertx;
        this.config = config;
        this.iamService = iamService;
    }

    /** Called by Ec2ContainerManager after a container starts to register its IP. */
    public void registerContainer(String containerIp, String instanceId, Instance instance) {
        if (containerIp != null && !containerIp.isBlank()) {
            containerIpToInstance.put(containerIp, instance);
            LOG.debugv("IMDS: registered container {0} → instance {1}", containerIp, instanceId);
        }
    }

    /** Called by Ec2ContainerManager when a container is terminated. */
    public void unregisterContainer(String containerIp, Instance instance) {
        if (containerIp != null && instance != null) {
            containerIpToInstance.remove(containerIp, instance);
            tokenToInstance.entrySet().removeIf(entry -> entry.getValue() == instance);
        }
    }

    /** Called by Ec2ContainerManager after an instance is permanently terminated. */
    public void unregisterInstance(Instance instance) {
        if (instance == null) {
            return;
        }
        containerIpToInstance.entrySet().removeIf(entry -> entry.getValue() == instance);
        tokenToInstance.entrySet().removeIf(entry -> entry.getValue() == instance);
        InstanceCredentialState state = instanceCredentials.remove(instance.getInstanceId());
        if (state != null && iamService != null) {
            state.issuedCredentials().keySet().forEach(iamService::unregisterSession);
        }
    }

    Optional<Instance> registeredContainer(String containerIp) {
        return Optional.ofNullable(containerIpToInstance.get(containerIp));
    }

    public CompletableFuture<Void> start() {
        CompletableFuture<Void> future = new CompletableFuture<>();
        int port = config.services().ec2().imdsPort();

        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());

        router.routeWithRegex(METADATA_VERSION_PATTERN).handler(ctx ->
                ctx.reroute(versionedPath(ctx.request().path())));

        router.get("/").handler(ctx -> handleDirectory(ctx,
                "1.0\n2009-04-04\n2014-11-05\n2021-03-23\nlatest"));
        router.get("/latest").handler(ctx -> handleDirectory(ctx, "dynamic/\nmeta-data/\nuser-data"));
        router.get("/latest/").handler(ctx -> handleDirectory(ctx, "dynamic/\nmeta-data/\nuser-data"));
        router.get("/latest/meta-data").handler(this::handleMetadataRoot);
        router.get("/latest/meta-data/").handler(this::handleMetadataRoot);
        router.get("/latest/meta-data/iam").handler(ctx -> handleDirectory(ctx, "info\nsecurity-credentials/"));
        router.get("/latest/meta-data/iam/").handler(ctx -> handleDirectory(ctx, "info\nsecurity-credentials/"));
        router.get("/latest/meta-data/placement").handler(ctx -> handleDirectory(ctx, "availability-zone\nregion"));
        router.get("/latest/meta-data/placement/").handler(ctx -> handleDirectory(ctx, "availability-zone\nregion"));
        router.get("/latest/meta-data/network").handler(ctx -> handleDirectory(ctx, "interfaces/"));
        router.get("/latest/meta-data/network/").handler(ctx -> handleDirectory(ctx, "interfaces/"));
        router.get("/latest/meta-data/network/interfaces").handler(ctx -> handleDirectory(ctx, "macs/"));
        router.get("/latest/meta-data/network/interfaces/").handler(ctx -> handleDirectory(ctx, "macs/"));
        router.get("/latest/meta-data/network/interfaces/macs").handler(this::handleNetworkMacs);
        router.get("/latest/meta-data/network/interfaces/macs/").handler(this::handleNetworkMacs);
        router.getWithRegex("/latest/meta-data/network/interfaces/macs/[^/]+/?")
                .handler(this::handleNetworkInterfaceDirectory);
        router.getWithRegex("/latest/meta-data/network/interfaces/macs/[^/]+/[^/]+")
                .handler(this::handleNetworkInterfaceValue);
        router.get("/latest/meta-data/tags").handler(ctx -> handleDirectory(ctx, "instance/"));
        router.get("/latest/meta-data/tags/").handler(ctx -> handleDirectory(ctx, "instance/"));
        router.get("/latest/dynamic").handler(ctx -> handleDirectory(ctx, "instance-identity/"));
        router.get("/latest/dynamic/").handler(ctx -> handleDirectory(ctx, "instance-identity/"));
        router.get("/latest/dynamic/instance-identity").handler(ctx -> handleDirectory(ctx, "document"));
        router.get("/latest/dynamic/instance-identity/").handler(ctx -> handleDirectory(ctx, "document"));

        // IMDSv2 token endpoint
        router.put("/latest/api/token").handler(this::handleToken);

        // Metadata endpoints
        router.get("/latest/meta-data/instance-id").handler(ctx -> handleText(ctx, inst -> inst.getInstanceId()));
        router.get("/latest/meta-data/ami-id").handler(ctx -> handleText(ctx, inst -> inst.getImageId()));
        router.get("/latest/meta-data/instance-type").handler(ctx -> handleText(ctx, inst -> inst.getInstanceType()));
        router.get("/latest/meta-data/local-ipv4").handler(ctx -> handleText(ctx, inst -> inst.getPrivateIpAddress()));
        router.get("/latest/meta-data/public-ipv4").handler(ctx -> handleText(ctx, inst -> inst.getPublicIpAddress()));
        router.get("/latest/meta-data/public-hostname").handler(ctx -> handleText(ctx, inst -> inst.getPublicDnsName()));
        router.get("/latest/meta-data/local-hostname").handler(ctx -> handleText(ctx, inst -> inst.getPrivateDnsName()));
        router.get("/latest/meta-data/hostname").handler(ctx -> handleText(ctx, inst -> inst.getPrivateDnsName()));
        router.get("/latest/meta-data/mac").handler(ctx -> handleMac(ctx));
        router.get("/latest/meta-data/security-groups").handler(ctx -> handleSecurityGroups(ctx));
        router.get("/latest/meta-data/placement/availability-zone").handler(ctx -> handleText(ctx, inst ->
                inst.getPlacement() != null ? inst.getPlacement().getAvailabilityZone() : "us-east-1a"));
        router.get("/latest/meta-data/placement/region").handler(ctx -> handleText(ctx, inst -> inst.getRegion()));
        router.get("/latest/meta-data/iam/info").handler(ctx -> handleIamInfo(ctx));
        router.get("/latest/meta-data/iam/security-credentials/").handler(ctx -> handleCredentialsList(ctx));
        router.get("/latest/meta-data/iam/security-credentials/:role").handler(ctx -> handleCredentials(ctx));
        router.get("/latest/meta-data/tags/instance").handler(ctx -> handleInstanceTagKeys(ctx));
        router.get("/latest/meta-data/tags/instance/").handler(ctx -> handleInstanceTagKeys(ctx));
        router.getWithRegex("/latest/meta-data/tags/instance/.+").handler(ctx -> handleInstanceTagValue(ctx));
        router.get("/latest/user-data").handler(ctx -> handleUserData(ctx));
        router.get("/latest/dynamic/instance-identity/document").handler(ctx -> handleIdentityDocument(ctx));

        httpServer = vertx.createHttpServer();
        httpServer.requestHandler(router).listen(port, result -> {
            if (result.succeeded()) {
                LOG.infof("EC2 IMDS server listening on port %d", port);
                future.complete(null);
            } else {
                LOG.warnf("EC2 IMDS server failed to start on port %d: %s", port, result.cause().getMessage());
                future.completeExceptionally(result.cause());
            }
        });
        return future;
    }

    public void stop() {
        if (httpServer != null) {
            httpServer.close();
        }
        tokenToInstance.clear();
        containerIpToInstance.clear();
        instanceCredentials.clear();
    }

    // ── Token (IMDSv2) ────────────────────────────────────────────────────────

    private void handleToken(RoutingContext ctx) {
        String ttlHeader = ctx.request().getHeader("x-aws-ec2-metadata-token-ttl-seconds");
        if (ttlHeader == null) {
            ctx.response().setStatusCode(400).end("Missing x-aws-ec2-metadata-token-ttl-seconds");
            return;
        }

        Instance inst = resolveInstanceByIp(ctx);
        String token = UUID.randomUUID().toString().replace("-", "");
        if (inst != null) {
            tokenToInstance.put(token, inst);
        }

        ctx.response()
                .setStatusCode(200)
                .putHeader("x-aws-ec2-metadata-token-ttl-seconds", ttlHeader)
                .end(token);
    }

    // ── Metadata helpers ──────────────────────────────────────────────────────

    @FunctionalInterface
    interface InstanceField {
        String get(Instance instance);
    }

    private void handleText(RoutingContext ctx, InstanceField field) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        String value = field.get(inst);
        if (value == null) {
            ctx.response().setStatusCode(404).end("not-available");
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(value);
    }

    private void handleDirectory(RoutingContext ctx, String contents) {
        if (resolveInstance(ctx) == null) {
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(contents);
    }

    private void handleMetadataRoot(RoutingContext ctx) {
        Instance instance = resolveInstance(ctx);
        if (instance == null) {
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(metadataRootDirectory(instance));
    }

    private void handleMac(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        String mac = inst.getNetworkInterfaces().isEmpty()
                ? "02:42:ac:11:00:02"
                : inst.getNetworkInterfaces().get(0).getMacAddress();
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(mac != null ? mac : "02:42:ac:11:00:02");
    }

    private void handleSecurityGroups(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (var sg : inst.getSecurityGroups()) {
            if (!sb.isEmpty()) {
                sb.append("\n");
            }
            sb.append(sg.getGroupName() != null ? sg.getGroupName() : sg.getGroupId());
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(sb.toString());
    }

    private void handleNetworkMacs(RoutingContext ctx) {
        Instance instance = resolveInstance(ctx);
        if (instance == null) {
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(networkMacDirectory(instance));
    }

    private void handleNetworkInterfaceDirectory(RoutingContext ctx) {
        Instance instance = resolveInstance(ctx);
        if (instance == null) {
            return;
        }
        Optional<InstanceNetworkInterface> networkInterface = networkInterface(instance, networkMac(ctx));
        if (networkInterface.isEmpty()) {
            ctx.response().setStatusCode(404).end("not-found");
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(networkInterfaceDirectory(networkInterface.get()));
    }

    private void handleNetworkInterfaceValue(RoutingContext ctx) {
        Instance instance = resolveInstance(ctx);
        if (instance == null) {
            return;
        }
        Optional<InstanceNetworkInterface> networkInterface = networkInterface(instance, networkMac(ctx));
        Optional<String> value = networkInterface.flatMap(attachedInterface -> networkInterfaceValue(
                attachedInterface,
                ctx.request().path().substring(ctx.request().path().lastIndexOf('/') + 1)));
        if (value.isEmpty()) {
            ctx.response().setStatusCode(404).end("not-available");
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(value.get());
    }

    private static String networkMac(RoutingContext ctx) {
        String prefix = "/latest/meta-data/network/interfaces/macs/";
        String suffix = ctx.request().path().substring(prefix.length());
        int slash = suffix.indexOf('/');
        return slash >= 0 ? suffix.substring(0, slash) : suffix;
    }

    private void handleIamInfo(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        String profileArn = inst.getIamInstanceProfileArn();
        if (profileArn == null) {
            ctx.response().setStatusCode(404).end("{}");
            return;
        }
        String profileId = "AIPA" + inst.getInstanceId().toUpperCase().substring(2, 16);
        String body = "{\"Code\":\"Success\",\"LastUpdated\":\"" + now() + "\","
                + "\"InstanceProfileArn\":\"" + profileArn + "\","
                + "\"InstanceProfileId\":\"" + profileId + "\"}";
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "application/json")
                .end(body);
    }

    private void handleCredentialsList(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        String profileArn = inst.getIamInstanceProfileArn();
        if (profileArn == null) {
            ctx.response().setStatusCode(404).end();
            return;
        }
        String roleName = resolveRoleName(profileArn);
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(roleName);
    }

    private void handleCredentials(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        if (inst.getIamInstanceProfileArn() == null) {
            ctx.response().setStatusCode(404).end();
            return;
        }

        String body = issueInstanceProfileCredentials(inst, Instant.now()).toJson();
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "application/json")
                .end(body);
    }

    private void handleInstanceTagKeys(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(instanceTagKeys(inst));
    }

    private void handleInstanceTagValue(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }

        String path = ctx.request().path();
        String tagKey = path.length() <= INSTANCE_TAGS_PREFIX.length()
                ? ""
                : URLDecoder.decode(path.substring(INSTANCE_TAGS_PREFIX.length()), StandardCharsets.UTF_8);
        Optional<String> value = instanceTagValue(inst, tagKey);
        if (value.isEmpty()) {
            ctx.response().setStatusCode(404).end("not-found");
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "text/plain")
                .end(value.get());
    }

    private void handleUserData(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        byte[] userData = userDataBytes(inst);
        if (userData == null) {
            ctx.response().setStatusCode(404).end();
            return;
        }
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "application/octet-stream")
                .end(Buffer.buffer(userData));
    }

    static byte[] userDataBytes(Instance instance) {
        if (instance.getEncodedUserData() != null) {
            return Ec2UserData.fromEncoded(instance.getEncodedUserData()).bytes();
        }
        return instance.getUserData() != null
                ? instance.getUserData().getBytes(StandardCharsets.UTF_8)
                : null;
    }

    private void handleIdentityDocument(RoutingContext ctx) {
        Instance inst = resolveInstance(ctx);
        if (inst == null) {
            return;
        }
        String body = instanceIdentityDocument(inst, config.defaultAccountId());
        ctx.response().setStatusCode(200)
                .putHeader("content-type", "application/json")
                .end(body);
    }

    static String instanceIdentityDocument(Instance inst, String accountId) {
        String az = inst.getPlacement() != null ? inst.getPlacement().getAvailabilityZone() : "us-east-1a";
        String architecture = inst.getArchitecture() == null || inst.getArchitecture().isBlank()
                ? "x86_64"
                : inst.getArchitecture();
        String body = "{\"accountId\":\"" + accountId + "\","
                + "\"architecture\":\"" + architecture + "\","
                + "\"availabilityZone\":\"" + az + "\","
                + "\"imageId\":\"" + inst.getImageId() + "\","
                + "\"instanceId\":\"" + inst.getInstanceId() + "\","
                + "\"instanceType\":\"" + inst.getInstanceType() + "\","
                + "\"privateIp\":\"" + nvl(inst.getPrivateIpAddress()) + "\","
                + "\"region\":\"" + inst.getRegion() + "\","
                + "\"version\":\"2017-09-30\"}";
        return body;
    }

    // ── Instance resolution ───────────────────────────────────────────────────

    private Instance resolveInstanceByIp(RoutingContext ctx) {
        String remoteIp = ctx.request().remoteAddress().host();
        return containerIpToInstance.get(remoteIp);
    }

    private Instance resolveInstance(RoutingContext ctx) {
        // Try IMDSv2 token first
        String token = ctx.request().getHeader("x-aws-ec2-metadata-token");
        if (token != null && !token.isBlank()) {
            Instance inst = tokenToInstance.get(token);
            if (inst != null) {
                return inst;
            }
        }

        // Fall back to source IP (IMDSv1)
        String remoteIp = ctx.request().remoteAddress().host();
        Instance inst = containerIpToInstance.get(remoteIp);
        if (inst == null) {
            LOG.warnv("IMDS: could not identify instance for request from {0}", remoteIp);
            ctx.response().setStatusCode(404).end("Instance not found");
        }
        return inst;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    String resolveRoleName(String profileArn) {
        if (iamService != null) {
            String profileName = extractProfileName(profileArn);
            try {
                var profile = iamService.getInstanceProfile(profileName);
                if (profile.getRoleNames() != null && !profile.getRoleNames().isEmpty()) {
                    return profile.getRoleNames().getFirst();
                }
            } catch (AwsException e) {
                LOG.debugf(e, "IMDS: instance profile %s unavailable; falling back to profile name", profileName);
                // Fall back to the profile name when only the EC2 profile ARN was modeled.
            }
        }
        return extractProfileName(profileArn);
    }

    private static String extractProfileName(String profileArn) {
        // arn:aws:iam::000000000000:instance-profile/my-role
        int lastSlash = profileArn.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < profileArn.length() - 1) {
            return profileArn.substring(lastSlash + 1);
        }
        return "instance-role";
    }

    private static String now() {
        return ISO.format(Instant.now());
    }

    private static String nvl(String s) {
        return s != null ? s : "";
    }

    InstanceProfileCredentials issueInstanceProfileCredentials(Instance instance, Instant now) {
        if (instance == null || instance.getInstanceId() == null) {
            throw new IllegalArgumentException("instance ID is required");
        }
        return instanceCredentials.compute(instance.getInstanceId(), (instanceId, previous) -> {
            previous = pruneExpiredCredentials(previous, now);
            String profileArn = nvl(instance.getIamInstanceProfileArn());
            if (previous != null
                    && previous.profileArn().equals(profileArn)
                    && now.isBefore(previous.current().expiration().minus(CREDENTIAL_ROTATION_WINDOW))) {
                return previous;
            }

            InstanceProfileCredentials current = newInstanceProfileCredentials(now);
            registerInstanceProfileCredentials(instance, current);
            Map<String, Instant> issuedCredentials = previous == null
                    ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(previous.issuedCredentials());
            issuedCredentials.put(current.accessKeyId(), current.expiration());
            return new InstanceCredentialState(profileArn, current, Map.copyOf(issuedCredentials));
        }).current();
    }

    private InstanceCredentialState pruneExpiredCredentials(
            InstanceCredentialState previous,
            Instant now) {
        if (previous == null) {
            return null;
        }
        Map<String, Instant> active = new LinkedHashMap<>(previous.issuedCredentials());
        active.entrySet().removeIf(entry -> {
            if (entry.getValue().isAfter(now)) {
                return false;
            }
            if (iamService != null) {
                iamService.unregisterSession(entry.getKey());
            }
            return true;
        });
        return active.size() == previous.issuedCredentials().size()
                ? previous
                : new InstanceCredentialState(previous.profileArn(), previous.current(), Map.copyOf(active));
    }

    Optional<InstanceProfileCredentials> cachedInstanceProfileCredentials(String instanceId) {
        return Optional.ofNullable(instanceCredentials.get(instanceId))
                .map(InstanceCredentialState::current);
    }

    private void registerInstanceProfileCredentials(
            Instance instance,
            InstanceProfileCredentials credentials) {
        if (iamService == null) {
            return;
        }
        String profileArn = instance.getIamInstanceProfileArn();
        String roleName = resolveRoleName(profileArn);
        IamRole role;
        try {
            role = iamService.getRole(roleName);
        } catch (AwsException e) {
            LOG.debugf(e, "IMDS: role %s unavailable while registering instance profile credentials", roleName);
            return;
        }
        String accountId = AwsArnUtils.accountOrDefault(profileArn, null);
        iamService.registerSession(
                credentials.accessKeyId(),
                credentials.secretAccessKey(),
                credentials.token(),
                role.getArn(),
                instance.getInstanceId(),
                accountId,
                role.getRoleId(),
                credentials.expiration(),
                null,
                accountId);
    }

    private static InstanceProfileCredentials newInstanceProfileCredentials(Instant issuedAt) {
        return new InstanceProfileCredentials(
                "ASIA" + randomUppercaseHex(8),
                randomBase64(30),
                randomBase64(64),
                issuedAt,
                issuedAt.plus(CREDENTIAL_LIFETIME));
    }

    private static String randomUppercaseHex(int byteCount) {
        byte[] bytes = new byte[byteCount];
        RANDOM.nextBytes(bytes);
        return java.util.HexFormat.of().withUpperCase().formatHex(bytes);
    }

    private static String randomBase64(int byteCount) {
        byte[] bytes = new byte[byteCount];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    record InstanceCredentialState(
            String profileArn,
            InstanceProfileCredentials current,
            Map<String, Instant> issuedCredentials) {
    }

    record InstanceProfileCredentials(
            String accessKeyId,
            String secretAccessKey,
            String token,
            Instant lastUpdated,
            Instant expiration) {

        String toJson() {
            return "{\"Code\":\"Success\","
                    + "\"LastUpdated\":\"" + ISO.format(lastUpdated) + "\","
                    + "\"Type\":\"AWS-HMAC\","
                    + "\"AccessKeyId\":\"" + accessKeyId + "\","
                    + "\"SecretAccessKey\":\"" + secretAccessKey + "\","
                    + "\"Token\":\"" + token + "\","
                    + "\"Expiration\":\"" + ISO.format(expiration) + "\"}";
        }
    }

    static String instanceTagKeys(Instance instance) {
        StringBuilder tags = new StringBuilder();
        if (instance == null || instance.getTags() == null) {
            return "";
        }
        for (var tag : instance.getTags()) {
            if (tag.getKey() == null || tag.getKey().isBlank()) {
                continue;
            }
            if (!tags.isEmpty()) {
                tags.append("\n");
            }
            tags.append(tag.getKey());
        }
        return tags.toString();
    }

    static Optional<String> instanceTagValue(Instance instance, String key) {
        if (instance == null || instance.getTags() == null || key == null) {
            return Optional.empty();
        }
        for (var tag : instance.getTags()) {
            if (key.equals(tag.getKey())) {
                return Optional.of(nvl(tag.getValue()));
            }
        }
        return Optional.empty();
    }

    static String versionedPath(String path) {
        if (path == null || path.length() < 12 || path.charAt(0) != '/') {
            return path;
        }
        int nextSlash = path.indexOf('/', 1);
        if (nextSlash < 0) {
            return "/latest";
        }
        return "/latest" + path.substring(nextSlash);
    }

    static String metadataRootDirectory(Instance instance) {
        java.util.List<String> entries = new java.util.ArrayList<>(java.util.List.of(
                "ami-id",
                "hostname",
                "instance-id",
                "instance-type",
                "local-hostname",
                "local-ipv4",
                "mac",
                "network/",
                "placement/",
                "security-groups",
                "tags/"));
        if (instance != null && instance.getIamInstanceProfileArn() != null) {
            entries.add(2, "iam/");
        }
        if (instance != null && instance.getPublicDnsName() != null) {
            entries.add("public-hostname");
        }
        if (instance != null && instance.getPublicIpAddress() != null) {
            entries.add("public-ipv4");
        }
        return String.join("\n", entries);
    }

    static String networkMacDirectory(Instance instance) {
        if (instance == null || instance.getNetworkInterfaces() == null) {
            return "";
        }
        return instance.getNetworkInterfaces().stream()
                .map(InstanceNetworkInterface::getMacAddress)
                .filter(mac -> mac != null && !mac.isBlank())
                .map(mac -> mac + "/")
                .collect(java.util.stream.Collectors.joining("\n"));
    }

    static Optional<InstanceNetworkInterface> networkInterface(Instance instance, String mac) {
        if (instance == null || instance.getNetworkInterfaces() == null || mac == null) {
            return Optional.empty();
        }
        return instance.getNetworkInterfaces().stream()
                .filter(networkInterface -> mac.equalsIgnoreCase(networkInterface.getMacAddress()))
                .findFirst();
    }

    static String networkInterfaceDirectory(InstanceNetworkInterface networkInterface) {
        java.util.List<String> entries = new java.util.ArrayList<>(java.util.List.of(
                "device-number",
                "interface-id",
                "local-hostname",
                "local-ipv4s",
                "mac",
                "owner-id",
                "security-group-ids",
                "security-groups",
                "subnet-id",
                "vpc-id"));
        return entries.stream()
                .filter(entry -> networkInterfaceValue(networkInterface, entry).isPresent())
                .collect(java.util.stream.Collectors.joining("\n"));
    }

    static Optional<String> networkInterfaceValue(InstanceNetworkInterface networkInterface, String field) {
        if (networkInterface == null || field == null) {
            return Optional.empty();
        }
        String value = switch (field) {
            case "device-number" -> Integer.toString(networkInterface.getDeviceIndex());
            case "interface-id" -> networkInterface.getNetworkInterfaceId();
            case "local-hostname" -> networkInterface.getPrivateDnsName();
            case "local-ipv4s" -> networkInterface.getPrivateIpAddress();
            case "mac" -> networkInterface.getMacAddress();
            case "owner-id" -> networkInterface.getOwnerId();
            case "security-group-ids" -> networkInterface.getGroups().stream()
                    .map(group -> group.getGroupId())
                    .filter(java.util.Objects::nonNull)
                    .collect(java.util.stream.Collectors.joining("\n"));
            case "security-groups" -> networkInterface.getGroups().stream()
                    .map(group -> group.getGroupName() != null ? group.getGroupName() : group.getGroupId())
                    .filter(java.util.Objects::nonNull)
                    .collect(java.util.stream.Collectors.joining("\n"));
            case "subnet-id" -> networkInterface.getSubnetId();
            case "vpc-id" -> networkInterface.getVpcId();
            default -> null;
        };
        return value == null || value.isBlank() ? Optional.empty() : Optional.of(value);
    }

}
