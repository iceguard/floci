package io.github.hectorvent.floci.services.rds.proxy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision.ALLOW;

/**
 * Validates RDS IAM auth tokens (SigV4 presigned URLs).
 * RDS tokens sign {@code host:port} in the canonical host header, unlike ElastiCache
 * which signs only the cluster hostname. The token format is:
 * {@code hostname:port/?Action=connect&DBUser=user&X-Amz-*=...}
 */
@ApplicationScoped
public class RdsSigV4Validator {

    private static final Logger LOG = Logger.getLogger(RdsSigV4Validator.class);
    private static final DateTimeFormatter DATETIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DATE_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);
    private static final int MAX_TOKEN_LIFETIME_SECONDS = 900;
    private static final int MAX_CLOCK_SKEW_SECONDS = 300;

    private final IamService iamService;
    private final IamPolicyEvaluator policyEvaluator;

    @Inject
    public RdsSigV4Validator(IamService iamService, IamPolicyEvaluator policyEvaluator) {
        this.iamService = iamService;
        this.policyEvaluator = policyEvaluator;
    }

    RdsSigV4Validator(IamService iamService) {
        this(iamService, new IamPolicyEvaluator(new ObjectMapper()));
    }

    /**
     * Validates an RDS IAM auth token.
     * The token is a presigned URL without the scheme, e.g.:
     * {@code hostname:port/?Action=connect&DBUser=admin&X-Amz-Signature=...}
     *
     * @param token the presigned URL token
     * @param clientUsername the username from the PostgreSQL startup message;
     *                       must match the {@code DBUser} in the token
     * @return true if the token signature is valid, the DBUser matches, and the token is not expired
     */
    public boolean validate(String token, String clientUsername) {
        return validateToken(token, clientUsername).isPresent();
    }

    /**
     * Validates the token and requires the caller to have {@code rds-db:connect}
     * permission for the exact database-user ARN.
     */
    public boolean validateAndAuthorize(String token, String clientUsername, String dbUserArn) {
        return validateAndAuthorize(token, clientUsername, dbUserArn, null, -1);
    }

    public boolean validateAndAuthorize(String token, String clientUsername, String dbUserArn,
                                        String expectedHost, int expectedPort) {
        String expectedRegion = arnRegion(dbUserArn);
        Optional<ValidatedToken> validated = validateToken(
                token, clientUsername, expectedHost, expectedPort, expectedRegion);
        if (validated.isEmpty()) {
            return false;
        }
        CallerContext caller = iamService.resolveCallerContext(validated.get().accessKeyId());
        if (caller == null) {
            LOG.debugv("RDS IAM token caller has no resolvable IAM identity: accessKey={0}",
                    validated.get().accessKeyId());
            return false;
        }
        return policyEvaluator.evaluate(caller, null, "rds-db:connect", dbUserArn, Map.of()) == ALLOW;
    }

    private Optional<ValidatedToken> validateToken(String token, String clientUsername) {
        return validateToken(token, clientUsername, null, -1, null);
    }

    private Optional<ValidatedToken> validateToken(String token, String clientUsername,
                                                   String expectedHost, int expectedPort,
                                                   String expectedRegion) {
        try {
            URI uri = URI.create("http://" + token);
            String host = uri.getHost();
            int port = uri.getPort();
            String rawQuery = uri.getRawQuery();

            if (host == null || rawQuery == null) {
                LOG.debugv("RDS IAM token missing host or query string");
                return Optional.empty();
            }

            // RDS tokens sign host:port in the canonical host header
            String authority = (port > 0) ? host + ":" + port : host;
            if (expectedHost != null && (!expectedHost.equalsIgnoreCase(host) || expectedPort != port)) {
                LOG.debugv("RDS IAM token endpoint mismatch: expected={0}:{1}, token={2}",
                        expectedHost, expectedPort, authority);
                return Optional.empty();
            }

            String[] rawPairs = rawQuery.split("&");
            String action = findRawParam(rawPairs, "Action");
            String dbUser = findRawParam(rawPairs, "DBUser");
            String dateTime = findRawParam(rawPairs, "X-Amz-Date");
            String expires = findRawParam(rawPairs, "X-Amz-Expires");
            String credential = findRawParam(rawPairs, "X-Amz-Credential");
            String sessionToken = findRawParam(rawPairs, "X-Amz-Security-Token");
            String signedHeaders = findRawParam(rawPairs, "X-Amz-SignedHeaders");
            String signature = findRawParam(rawPairs, "X-Amz-Signature");
            String algorithm = findRawParam(rawPairs, "X-Amz-Algorithm");

            if (!"connect".equals(action) || dbUser == null || dateTime == null || expires == null
                    || credential == null || signature == null
                    || !"AWS4-HMAC-SHA256".equals(algorithm) || !"host".equals(signedHeaders)) {
                LOG.debugv("RDS IAM token missing required SigV4 parameters");
                return Optional.empty();
            }

            if (clientUsername != null && !clientUsername.equals(dbUser)) {
                LOG.debugv("RDS IAM token DBUser mismatch: client={0}, token={1}",
                        clientUsername, dbUser);
                return Optional.empty();
            }

            Instant tokenTime = Instant.from(DATETIME_FMT.parse(dateTime));
            int expirySeconds = Integer.parseInt(expires);
            Instant now = Instant.now();
            if (expirySeconds <= 0 || expirySeconds > MAX_TOKEN_LIFETIME_SECONDS
                    || tokenTime.isAfter(now.plusSeconds(MAX_CLOCK_SKEW_SECONDS))
                    || now.isAfter(tokenTime.plusSeconds(expirySeconds))) {
                LOG.debugv("RDS IAM token expired");
                return Optional.empty();
            }

            String decodedCredential = urlDecode(credential);
            String[] credParts = decodedCredential.split("/");
            if (credParts.length < 5) {
                return Optional.empty();
            }
            String accessKeyId = credParts[0];
            String date = credParts[1];
            String region = credParts[2];
            String service = credParts[3];
            if (!DATE_FMT.format(tokenTime).equals(date)) {
                LOG.debugv("RDS IAM token credential date does not match X-Amz-Date");
                return Optional.empty();
            }
            if (!"rds-db".equals(service) || !"aws4_request".equals(credParts[4])) {
                LOG.debugv("RDS IAM token has invalid credential scope service={0}", service);
                return Optional.empty();
            }
            if (expectedRegion != null && !expectedRegion.equals(region)) {
                LOG.debugv("RDS IAM token region mismatch: expected={0}, token={1}",
                        expectedRegion, region);
                return Optional.empty();
            }
            String credentialScope = date + "/" + region + "/" + service + "/aws4_request";

            if (!accessKeyId.startsWith("ASIA") && sessionToken != null) {
                LOG.debugv("RDS IAM token has a session token for long-term accessKey={0}", accessKeyId);
                return Optional.empty();
            }
            String secretKey = iamService.findSigningSecret(accessKeyId, sessionToken).orElse(null);
            if (secretKey == null) {
                LOG.debugv("RDS IAM token has invalid temporary credentials for accessKey={0}", accessKeyId);
                return Optional.empty();
            }

            // Canonical query string: sorted pairs, excluding X-Amz-Signature
            String canonicalQueryString = Arrays.stream(rawPairs)
                    .filter(p -> !rawParamName(p).equals("X-Amz-Signature"))
                    .sorted((a, b) -> rawParamName(a).compareTo(rawParamName(b)))
                    .collect(Collectors.joining("&"));

            // Canonical request: RDS uses host:port as the host header value
            String canonicalRequest = "GET\n/\n"
                    + canonicalQueryString + "\n"
                    + "host:" + authority + "\n\n"
                    + "host\n"
                    + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // sha256("")

            String stringToSign = "AWS4-HMAC-SHA256\n"
                    + dateTime + "\n"
                    + credentialScope + "\n"
                    + sha256Hex(canonicalRequest);

            byte[] signingKey = deriveSigningKey(secretKey, date, region, service);
            String expectedSignature = hexEncode(hmacSha256(signingKey, stringToSign));

            boolean valid = MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.UTF_8),
                    signature.getBytes(StandardCharsets.UTF_8));
            if (!valid) {
                LOG.debugv("RDS IAM token signature mismatch for accessKey={0}", accessKeyId);
            }
            return valid
                    ? Optional.of(new ValidatedToken(accessKeyId))
                    : Optional.empty();

        } catch (Exception e) {
            LOG.debugv("RDS IAM token validation error: {0}", e.getMessage());
            return Optional.empty();
        }
    }

    private record ValidatedToken(String accessKeyId) {}

    private static String arnRegion(String arn) {
        if (arn == null) {
            return null;
        }
        String[] parts = arn.split(":", 6);
        return parts.length == 6 && !parts[3].isBlank() ? parts[3] : null;
    }

    private static String rawParamName(String rawPair) {
        int eq = rawPair.indexOf('=');
        return eq >= 0 ? rawPair.substring(0, eq) : rawPair;
    }

    private static String findRawParam(String[] rawPairs, String name) {
        for (String pair : rawPairs) {
            int eq = pair.indexOf('=');
            if (eq >= 0 && name.equals(pair.substring(0, eq))) {
                return urlDecode(pair.substring(eq + 1));
            }
        }
        return null;
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static byte[] deriveSigningKey(String secretKey, String date, String region,
                                           String service) throws Exception {
        byte[] kSecret = ("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSha256(kSecret, date);
        byte[] kRegion = hmacSha256(kDate, region);
        byte[] kService = hmacSha256(kRegion, service);
        return hmacSha256(kService, "aws4_request");
    }

    private static byte[] hmacSha256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return hexEncode(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    private static String hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
