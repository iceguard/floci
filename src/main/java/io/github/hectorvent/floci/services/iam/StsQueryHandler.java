package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsNamespaces;
import io.github.hectorvent.floci.core.common.AwsQueryController;
import io.github.hectorvent.floci.core.common.AwsQueryResponse;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.XmlBuilder;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.SessionCredential.SessionType;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.security.SecureRandom;
import java.util.Optional;

/**
 * Query-protocol handler for STS (Security Token Service) actions.
 * Receives pre-dispatched calls from {@link AwsQueryController}.
 * All responses use the STS XML namespace {@code https://sts.amazonaws.com/doc/2011-06-15/}.
 */
@ApplicationScoped
public class StsQueryHandler {

    private static final Logger LOG = Logger.getLogger(StsQueryHandler.class);
    private static final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final IamService iamService;
    private final AccountResolver accountResolver;
    private final RegionResolver regionResolver;
    private final EmulatorConfig config;
    private final AssumeRolePolicyEvaluator trustPolicyEvaluator;

    @Context
    HttpHeaders headers;

    @Context
    UriInfo uriInfo;

    @Inject
    public StsQueryHandler(IamService iamService, AccountResolver accountResolver, RegionResolver regionResolver,
                           EmulatorConfig config, AssumeRolePolicyEvaluator trustPolicyEvaluator) {
        this.iamService = iamService;
        this.accountResolver = accountResolver;
        this.regionResolver = regionResolver;
        this.config = config;
        this.trustPolicyEvaluator = trustPolicyEvaluator;
    }

    public Response handle(String action, MultivaluedMap<String, String> params) {
        LOG.debugv("STS action: {0}", action);

        return switch (action) {
            case "AssumeRole"                  -> handleAssumeRole(params);
            case "GetCallerIdentity"           -> handleGetCallerIdentity(params);
            case "GetSessionToken"             -> handleGetSessionToken(params);
            case "AssumeRoleWithWebIdentity"   -> handleAssumeRoleWithWebIdentity(params);
            case "AssumeRoleWithSAML"          -> handleAssumeRoleWithSAML(params);
            case "GetFederationToken"          -> handleGetFederationToken(params);
            case "DecodeAuthorizationMessage"  -> handleDecodeAuthorizationMessage(params);
            default -> AwsQueryResponse.error("UnsupportedOperation",
                    "Operation " + action + " is not supported by STS.", AwsNamespaces.STS, 400);
        };
    }

    private Response handleAssumeRole(MultivaluedMap<String, String> params) {
        Response validation = validateRequired(params, "RoleArn", "RoleSessionName");
        if (validation != null) {
            return validation;
        }
        String roleArn = getParam(params, "RoleArn");
        String sessionName = getParam(params, "RoleSessionName");
        int durationSeconds = getIntParam(params, "DurationSeconds", 3600);

        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);

        String roleName = roleArn != null && roleArn.contains("/")
                ? roleArn.substring(roleArn.lastIndexOf('/') + 1)
                : "UnknownRole";
        String callerAccountId = regionResolver.getAccountId();
        String accountId = AwsArnUtils.accountOrDefault(roleArn, callerAccountId);
        Optional<RolePrincipal> rolePrincipal = resolveRolePrincipal(accountId, roleName);
        if (rolePrincipal.isEmpty()) {
            return unknownRole(roleArn);
        }

        Response trustDenied = enforceTrustPolicy(roleArn, roleName, accountId, params);
        if (trustDenied != null) {
            return trustDenied;
        }

        String assumedRoleArn = AwsArnUtils.Arn.of("sts", "", accountId, "assumed-role/" + roleName + "/" + sessionName).toString();
        String assumedRoleId = rolePrincipal.get().id() + ":" + sessionName;

        // Register session so IAM enforcement can resolve the role's policies, RDS/ElastiCache
        // IAM token validation can find the temporary secret key, and account routing can map
        // these temporary credentials to the assumed role's account.
        String sessionPolicy = getParam(params, "Policy");
        iamService.registerSession(accessKeyId, secretKey, sessionToken, roleArn, sessionName,
                accountId, rolePrincipal.get().id(), expiration, sessionPolicy, callerAccountId,
                null, null, SessionType.ASSUME_ROLE, false, true);

        String result = new XmlBuilder()
                .raw(credentialsXml(accessKeyId, secretKey, sessionToken, expiration))
                .start("AssumedRoleUser")
                  .elem("Arn", assumedRoleArn)
                  .elem("AssumedRoleId", assumedRoleId)
                .end("AssumedRoleUser")
                .elem("PackedPolicySize", "0")
                .build();
        return Response.ok(AwsQueryResponse.envelope("AssumeRole", AwsNamespaces.STS, result)).build();
    }

    /**
     * When IAM enforcement is enabled, denies AssumeRole if the target role's trust policy does not
     * permit the caller. Target-role existence is validated before this method is called.
     */
    private Response enforceTrustPolicy(String roleArn, String roleName, String roleAccountId,
                                        MultivaluedMap<String, String> params) {
        if (!config.services().iam().enforcementEnabled()) {
            return null;
        }
        Optional<IamRole> role = iamService.findRole(roleAccountId, roleName);
        if (role.isEmpty()) {
            return null;
        }
        String auth = headers == null ? null : headers.getHeaderString("Authorization");
        String accessKeyId = requestAccessKeyId(auth);
        String sessionToken = securityToken(params);
        String callerAccount = IamService.isTemporaryAccessKey(accessKeyId)
                ? iamService.resolveSessionIdentity(accessKeyId, sessionToken).accountId()
                : regionResolver.getAccountId();
        String callerArn = iamService.resolveCallerArn(accessKeyId, sessionToken)
                .orElse(AwsArnUtils.Arn.of("iam", "", callerAccount, "root").toString());
        if (trustPolicyEvaluator.allows(role.get().getAssumeRolePolicyDocument(), callerArn, callerAccount)) {
            return null;
        }
        return AwsQueryResponse.error("AccessDenied",
                "User: " + callerArn + " is not authorized to perform: sts:AssumeRole on resource: " + roleArn,
                AwsNamespaces.STS, 403);
    }

    private Response handleGetCallerIdentity(MultivaluedMap<String, String> params) {
        String accountId = regionResolver.getAccountId();
        String authorization = headers == null ? null : headers.getHeaderString("Authorization");
        String accessKeyId = requestAccessKeyId(authorization);
        IamService.SessionIdentity sessionIdentity = IamService.isTemporaryAccessKey(accessKeyId)
                ? iamService.resolveSessionIdentity(accessKeyId, securityToken(params)) : null;
        String arn = sessionIdentity == null
                ? iamService.resolveCallerArn(accessKeyId)
                        .orElse(AwsArnUtils.Arn.of("iam", "", accountId, "root").toString())
                : sessionIdentity.arn();
        String userId = sessionIdentity == null ? accountId : sessionIdentity.userId();
        accountId = sessionIdentity == null ? accountId : sessionIdentity.accountId();
        String result = new XmlBuilder()
                .elem("UserId", userId)
                .elem("Account", accountId)
                .elem("Arn", arn)
                .build();
        return Response.ok(AwsQueryResponse.envelope("GetCallerIdentity", AwsNamespaces.STS, result)).build();
    }

    private Response handleGetSessionToken(MultivaluedMap<String, String> params) {
        String authorization = headers == null ? null : headers.getHeaderString("Authorization");
        String sourceAccessKeyId = requestAccessKeyId(authorization);
        if (IamService.isTemporaryAccessKey(sourceAccessKeyId)) {
            return AwsQueryResponse.error("AccessDenied",
                    "Cannot call GetSessionToken with session credentials",
                    AwsNamespaces.STS, 403);
        }
        String serialNumber = getParam(params, "SerialNumber");
        String tokenCode = getParam(params, "TokenCode");
        boolean serialPresent = serialNumber != null && !serialNumber.isBlank();
        boolean tokenPresent = tokenCode != null && !tokenCode.isBlank();
        if (serialPresent != tokenPresent || (tokenPresent && !tokenCode.matches("\\d{6}"))) {
            return AwsQueryResponse.error("ValidationError",
                    "SerialNumber and a six-digit TokenCode must be provided together",
                    AwsNamespaces.STS, 400);
        }
        if (serialPresent) {
            return AwsQueryResponse.error("AccessDenied",
                    "MultiFactorAuthentication failed with invalid MFA one time pass code.",
                    AwsNamespaces.STS, 403);
        }

        int durationSeconds = getIntParam(params, "DurationSeconds", 43200);
        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);

        String result = credentialsXml(accessKeyId, secretKey, sessionToken, expiration);
        String accountId = regionResolver.getAccountId();
        Optional<String> sourceArn = iamService.resolveCallerArn(sourceAccessKeyId, securityToken(params));
        String sourcePrincipalArn = sourceArn.orElseGet(
                () -> AwsArnUtils.Arn.of("iam", "", accountId, "root").toString());
        Optional<String> boundPrincipalId = iamService.resolveCallerPrincipalId(sourceAccessKeyId);
        String sourcePrincipalId = boundPrincipalId.orElse(accountId);
        iamService.registerSession(accessKeyId, secretKey, sessionToken, null, null,
                accountId, accountId, expiration, null, accountId,
                sourcePrincipalArn, sourcePrincipalId, SessionType.GET_SESSION_TOKEN,
                false, boundPrincipalId.isPresent());
        return Response.ok(AwsQueryResponse.envelope("GetSessionToken", AwsNamespaces.STS, result)).build();
    }

    private Response handleAssumeRoleWithWebIdentity(MultivaluedMap<String, String> params) {
        Response validation = validateRequired(params, "RoleArn", "RoleSessionName", "WebIdentityToken");
        if (validation != null) {
            return validation;
        }
        String roleArn = getParam(params, "RoleArn");
        String sessionName = getParam(params, "RoleSessionName");
        String providerId = getParam(params, "ProviderId");
        int durationSeconds = getIntParam(params, "DurationSeconds", 3600);

        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);

        String roleName = roleArn.contains("/") ? roleArn.substring(roleArn.lastIndexOf('/') + 1) : "UnknownRole";
        String callerAccountId = regionResolver.getAccountId();
        String accountId = AwsArnUtils.accountOrDefault(roleArn, callerAccountId);
        String assumedRoleArn = AwsArnUtils.Arn.of("sts", "", accountId, "assumed-role/" + roleName + "/" + sessionName).toString();
        Optional<RolePrincipal> rolePrincipal = resolveRolePrincipal(accountId, roleName);
        if (rolePrincipal.isEmpty()) {
            return unknownRole(roleArn);
        }
        String assumedRoleId = rolePrincipal.get().id() + ":" + sessionName;
        String provider = providerId != null && !providerId.isBlank() ? providerId : "accounts.google.com";

        String sessionPolicy = getParam(params, "Policy");
        iamService.registerSession(accessKeyId, secretKey, sessionToken, roleArn, sessionName,
                accountId, rolePrincipal.get().id(), expiration, sessionPolicy, callerAccountId,
                null, null, SessionType.WEB_IDENTITY, false, true);

        String result = new XmlBuilder()
                .raw(credentialsXml(accessKeyId, secretKey, sessionToken, expiration))
                .start("AssumedRoleUser")
                  .elem("Arn", assumedRoleArn)
                  .elem("AssumedRoleId", assumedRoleId)
                .end("AssumedRoleUser")
                .elem("PackedPolicySize", "0")
                .elem("Provider", provider)
                .elem("Audience", "sts.amazonaws.com")
                .elem("SubjectFromWebIdentityToken", "web-identity-subject")
                .build();
        return Response.ok(AwsQueryResponse.envelope("AssumeRoleWithWebIdentity", AwsNamespaces.STS, result)).build();
    }

    private Response handleAssumeRoleWithSAML(MultivaluedMap<String, String> params) {
        Response validation = validateRequired(params, "RoleArn", "PrincipalArn", "SAMLAssertion");
        if (validation != null) {
            return validation;
        }
        String roleArn = getParam(params, "RoleArn");
        String sessionName = "saml-session";
        int durationSeconds = getIntParam(params, "DurationSeconds", 3600);

        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);

        String roleName = roleArn.contains("/") ? roleArn.substring(roleArn.lastIndexOf('/') + 1) : "UnknownRole";
        String callerAccountId = regionResolver.getAccountId();
        String accountId = AwsArnUtils.accountOrDefault(roleArn, callerAccountId);
        String assumedRoleArn = AwsArnUtils.Arn.of("sts", "", accountId, "assumed-role/" + roleName + "/" + sessionName).toString();
        Optional<RolePrincipal> rolePrincipal = resolveRolePrincipal(accountId, roleName);
        if (rolePrincipal.isEmpty()) {
            return unknownRole(roleArn);
        }
        String assumedRoleId = rolePrincipal.get().id() + ":" + sessionName;

        iamService.registerSession(accessKeyId, secretKey, sessionToken, roleArn, sessionName,
                accountId, rolePrincipal.get().id(), expiration, null, callerAccountId,
                null, null, SessionType.SAML, false, true);

        String result = new XmlBuilder()
                .raw(credentialsXml(accessKeyId, secretKey, sessionToken, expiration))
                .start("AssumedRoleUser")
                  .elem("Arn", assumedRoleArn)
                  .elem("AssumedRoleId", assumedRoleId)
                .end("AssumedRoleUser")
                .elem("PackedPolicySize", "0")
                .elem("Issuer", "https://saml.example.com")
                .elem("Audience", "urn:amazon:webservices")
                .elem("NameQualifier", "saml-qualifier")
                .elem("SubjectType", "persistent")
                .elem("Subject", "saml-subject")
                .build();
        return Response.ok(AwsQueryResponse.envelope("AssumeRoleWithSAML", AwsNamespaces.STS, result)).build();
    }

    private Response handleGetFederationToken(MultivaluedMap<String, String> params) {
        Response validation = validateRequired(params, "Name");
        if (validation != null) {
            return validation;
        }
        String name = getParam(params, "Name");
        int durationSeconds = getIntParam(params, "DurationSeconds", 43200);

        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);
        String accountId = regionResolver.getAccountId();
        String federatedUserId = accountId + ":" + name;
        String federatedUserArn = AwsArnUtils.Arn.of("sts", "", accountId, "federated-user/" + name).toString();

        String sessionPolicy = getParam(params, "Policy");
        // Register federation token so enforcement can scope its policies via session policy.
        // The federated-user ARN already carries the caller's account, so reuse it as the origin.
        iamService.registerSession(accessKeyId, secretKey, sessionToken, federatedUserArn, name,
                accountId, federatedUserId, expiration, sessionPolicy, accountId,
                null, null, SessionType.FEDERATION_TOKEN, false, false);

        String result = new XmlBuilder()
                .raw(credentialsXml(accessKeyId, secretKey, sessionToken, expiration))
                .start("FederatedUser")
                  .elem("FederatedUserId", federatedUserId)
                  .elem("Arn", federatedUserArn)
                .end("FederatedUser")
                .elem("PackedPolicySize", "0")
                .build();
        return Response.ok(AwsQueryResponse.envelope("GetFederationToken", AwsNamespaces.STS, result)).build();
    }

    private Response handleDecodeAuthorizationMessage(MultivaluedMap<String, String> params) {
        Response validation = validateRequired(params, "EncodedMessage");
        if (validation != null) {
            return validation;
        }
        String encodedMessage = getParam(params, "EncodedMessage");
        String result = new XmlBuilder().elem("DecodedMessage", encodedMessage).build();
        return Response.ok(AwsQueryResponse.envelope("DecodeAuthorizationMessage", AwsNamespaces.STS, result)).build();
    }

    private Response validateRequired(MultivaluedMap<String, String> params, String... names) {
        for (String name : names) {
            String value = params.getFirst(name);
            if (value == null || value.isBlank()) {
                return AwsQueryResponse.error("ValidationError",
                        "1 validation error detected: Value null at '" + name
                        + "' failed to satisfy constraint: Member must not be null",
                        AwsNamespaces.STS, 400);
            }
        }
        return null;
    }

    private String credentialsXml(String accessKeyId, String secretKey, String sessionToken, Instant expiration) {
        return new XmlBuilder()
                .start("Credentials")
                  .elem("AccessKeyId", accessKeyId)
                  .elem("SecretAccessKey", secretKey)
                  .elem("SessionToken", sessionToken)
                  .elem("Expiration", isoDate(expiration))
                .end("Credentials")
                .build();
    }

    private Optional<RolePrincipal> resolveRolePrincipal(String accountId, String roleName) {
        return iamService.findRole(accountId, roleName)
                .map(role -> new RolePrincipal(role.getRoleId()));
    }

    private Response unknownRole(String roleArn) {
        return AwsQueryResponse.error("AccessDenied",
                "User is not authorized to perform: sts:AssumeRole on resource: " + roleArn,
                AwsNamespaces.STS, 403);
    }

    private String securityToken(MultivaluedMap<String, String> params) {
        String headerToken = headers == null ? null : headers.getHeaderString("X-Amz-Security-Token");
        if (headerToken != null && !headerToken.isBlank()) {
            return headerToken;
        }
        String formToken = getParam(params, "X-Amz-Security-Token");
        return formToken == null || formToken.isBlank()
                ? queryParam("X-Amz-Security-Token") : formToken;
    }

    private String requestAccessKeyId(String authorization) {
        if (authorization != null && !authorization.isBlank()) {
            return accountResolver.extractAccessKeyId(authorization);
        }
        String credential = queryParam("X-Amz-Credential");
        return credential == null ? null : accountResolver.extractPresignedAccessKeyId(credential);
    }

    private String queryParam(String name) {
        return uriInfo == null ? null : uriInfo.getQueryParameters().getFirst(name);
    }

    private String getParam(MultivaluedMap<String, String> params, String name) {
        return params.getFirst(name);
    }

    private int getIntParam(MultivaluedMap<String, String> params, String name, int defaultValue) {
        String value = params.getFirst(name);
        if (value == null) return defaultValue;
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private String isoDate(Instant instant) {
        return DateTimeFormatter.ISO_INSTANT.format(instant);
    }

    private static String randomId(int length) {
        StringBuilder sb = new StringBuilder(length);
        String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (int i = 0; i < length; i++) {
            sb.append(upper.charAt(SECURE_RANDOM.nextInt(upper.length())));
        }
        return sb.toString();
    }

    private static String randomSecret(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARS.charAt(SECURE_RANDOM.nextInt(CHARS.length())));
        }
        return sb.toString();
    }

    private record RolePrincipal(String id) {}
}
