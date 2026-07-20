package io.github.hectorvent.floci.services.servicequotas;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

@ApplicationScoped
public class ServiceQuotasJsonHandler {

    private static final int DEFAULT_MAX_RESULTS = 100;
    private static final int MAX_RESULTS_LIMIT = 100;
    private static final int SERVICE_CODE_MAX_LENGTH = 63;
    private static final int QUOTA_CODE_MAX_LENGTH = 128;
    private static final int NEXT_TOKEN_MAX_LENGTH = 2048;
    private static final String SERVICE_CODE_PATTERN_TEXT = "[a-zA-Z][a-zA-Z0-9-]{1,63}";
    private static final String QUOTA_CODE_PATTERN_TEXT = "[a-zA-Z][a-zA-Z0-9-]{1,128}";
    private static final String NEXT_TOKEN_PATTERN_TEXT = "^[a-zA-Z0-9/+]*={0,2}$";
    private static final Pattern SERVICE_CODE_PATTERN = Pattern.compile(SERVICE_CODE_PATTERN_TEXT);
    private static final Pattern QUOTA_CODE_PATTERN = Pattern.compile(QUOTA_CODE_PATTERN_TEXT);
    private static final Pattern NEXT_TOKEN_PATTERN = Pattern.compile(NEXT_TOKEN_PATTERN_TEXT);
    private static final Set<String> APPLIED_LEVELS = Set.of("ACCOUNT", "RESOURCE", "ALL");

    private final ObjectMapper mapper;
    private final RegionResolver regionResolver;
    private final EmulatorConfig.ServiceQuotasServiceConfig config;

    @Inject
    public ServiceQuotasJsonHandler(ObjectMapper mapper,
                                    RegionResolver regionResolver,
                                    EmulatorConfig emulatorConfig) {
        this(mapper, regionResolver, emulatorConfig.services().servicequotas());
    }

    ServiceQuotasJsonHandler(ObjectMapper mapper,
                             RegionResolver regionResolver,
                             EmulatorConfig.ServiceQuotasServiceConfig config) {
        this.mapper = mapper;
        this.regionResolver = regionResolver;
        this.config = config;
    }

    public Response handle(String action, JsonNode request, String region) {
        return switch (action) {
            case "GetServiceQuota", "GetAWSDefaultServiceQuota" -> getQuota(action, request, region);
            case "ListServiceQuotas", "ListAWSDefaultServiceQuotas" -> listQuotas(action, request, region);
            case "ListServices" -> listServices(request);
            default -> throw new AwsException("UnsupportedOperationException",
                    "Operation " + action + " is not supported.", 400);
        };
    }

    private Response getQuota(String action, JsonNode request, String region) {
        String serviceCode = requiredString(request, "ServiceCode",
                SERVICE_CODE_MAX_LENGTH, SERVICE_CODE_PATTERN, SERVICE_CODE_PATTERN_TEXT);
        String quotaCode = requiredString(request, "QuotaCode",
                QUOTA_CODE_MAX_LENGTH, QUOTA_CODE_PATTERN, QUOTA_CODE_PATTERN_TEXT);
        ServiceQuotaCatalog.ServiceDefinition service = ServiceQuotaCatalog.service(serviceCode)
                .orElseThrow(ServiceQuotasJsonHandler::noSuchResource);
        ServiceQuotaCatalog.QuotaDefinition quota = ServiceQuotaCatalog.find(serviceCode, quotaCode)
                .orElseThrow(ServiceQuotasJsonHandler::noSuchResource);
        if ("GetServiceQuota".equals(action) && optionalTypedString(request, "ContextId") != null) {
            throw noSuchResource();
        }

        ObjectNode response = mapper.createObjectNode();
        response.set("Quota", quotaNode(service, quota, region, isAwsDefaultAction(action)));
        return Response.ok(response).build();
    }

    private Response listQuotas(String action, JsonNode request, String region) {
        String serviceCode = requiredString(request, "ServiceCode",
                SERVICE_CODE_MAX_LENGTH, SERVICE_CODE_PATTERN, SERVICE_CODE_PATTERN_TEXT);
        ServiceQuotaCatalog.ServiceDefinition service = ServiceQuotaCatalog.service(serviceCode)
                .orElseThrow(ServiceQuotasJsonHandler::noSuchResource);
        List<ServiceQuotaCatalog.QuotaDefinition> quotas = ServiceQuotaCatalog.forService(serviceCode);
        String scope = serviceCode;
        if ("ListServiceQuotas".equals(action)) {
            String quotaCode = optionalString(request, "QuotaCode",
                    1, QUOTA_CODE_MAX_LENGTH, QUOTA_CODE_PATTERN, QUOTA_CODE_PATTERN_TEXT);
            String appliedLevel = appliedLevel(request);
            quotas = quotas.stream()
                    .filter(quota -> quotaCode == null || quota.code().equals(quotaCode))
                    .filter(quota -> "ALL".equals(appliedLevel)
                            || quota.appliedAtLevel().equals(appliedLevel))
                    .toList();
            scope += "," + (quotaCode == null ? "" : quotaCode) + "," + appliedLevel;
        }

        Page<ServiceQuotaCatalog.QuotaDefinition> page = page(action, scope, quotas, request);
        ObjectNode response = mapper.createObjectNode();
        ArrayNode values = response.putArray("Quotas");
        boolean awsDefault = isAwsDefaultAction(action);
        page.items().forEach(quota -> values.add(quotaNode(service, quota, region, awsDefault)));
        if (page.nextToken() != null) {
            response.put("NextToken", page.nextToken());
        }
        return Response.ok(response).build();
    }

    private Response listServices(JsonNode request) {
        List<ObjectNode> services = ServiceQuotaCatalog.services().stream()
                .map(service -> {
                    ObjectNode node = mapper.createObjectNode();
                    node.put("ServiceCode", service.code());
                    node.put("ServiceName", service.name());
                    return node;
                })
                .toList();

        Page<ObjectNode> page = page("ListServices", "services", services, request);
        ObjectNode response = mapper.createObjectNode();
        ArrayNode values = response.putArray("Services");
        page.items().forEach(values::add);
        if (page.nextToken() != null) {
            response.put("NextToken", page.nextToken());
        }
        return Response.ok(response).build();
    }

    private ObjectNode quotaNode(ServiceQuotaCatalog.ServiceDefinition service,
                                 ServiceQuotaCatalog.QuotaDefinition quota,
                                 String region,
                                 boolean awsDefault) {
        ObjectNode node = mapper.createObjectNode();
        node.put("ServiceCode", service.code());
        node.put("ServiceName", service.name());
        node.put("QuotaArn", "arn:aws:servicequotas:" + region + ":" + regionResolver.getAccountId()
                + ":" + service.code() + "/" + quota.code());
        node.put("QuotaCode", quota.code());
        node.put("QuotaName", quota.name());
        node.put("Value", awsDefault
                ? quota.awsDefaultValue()
                : ServiceQuotaCatalog.appliedValue(config, service.code(), quota.code()).orElseThrow());
        node.put("Unit", "None");
        node.put("Adjustable", quota.adjustable());
        node.put("GlobalQuota", quota.global());
        node.put("QuotaAppliedAtLevel", quota.appliedAtLevel());
        return node;
    }

    private <T> Page<T> page(String action, String scope, List<T> items, JsonNode request) {
        int maxResults = maxResults(request);
        String requestedToken = optionalString(request, "NextToken",
                0, NEXT_TOKEN_MAX_LENGTH, NEXT_TOKEN_PATTERN, NEXT_TOKEN_PATTERN_TEXT);
        int offset = decodeToken(action, scope, requestedToken);
        if (requestedToken != null && (offset <= 0 || offset >= items.size())) {
            throw invalidPaginationToken();
        }

        int end = Math.min(offset + maxResults, items.size());
        String nextToken = end < items.size() ? encodeToken(action, scope, end) : null;
        return new Page<>(items.subList(offset, end), nextToken);
    }

    private int maxResults(JsonNode request) {
        JsonNode value = request == null ? null : request.get("MaxResults");
        if (value == null || value.isNull()) {
            return DEFAULT_MAX_RESULTS;
        }
        if (!value.isIntegralNumber() || !value.canConvertToInt()
                || value.asLong() < 1 || value.asLong() > MAX_RESULTS_LIMIT) {
            if (!value.isIntegralNumber()) {
                throw invalidArgument("Value at 'maxResults' failed to satisfy constraint: "
                        + "Member must be an integer");
            }
            String constraint = value.asLong() < 1
                    ? "Member must have value greater than or equal to 1"
                    : "Member must have value less than or equal to " + MAX_RESULTS_LIMIT;
            throw invalidArgument("Value '" + value.asText() + "' at 'maxResults' "
                    + "failed to satisfy constraint: " + constraint);
        }
        return value.asInt();
    }

    private static int decodeToken(String action, String scope, String token) {
        if (token == null) {
            return 0;
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8);
            String[] parts = decoded.split(":", -1);
            if (parts.length != 3 || !action.equals(parts[0]) || !scope.equals(parts[1])) {
                throw invalidPaginationToken();
            }
            int offset = Integer.parseInt(parts[2]);
            if (offset < 0) {
                throw invalidPaginationToken();
            }
            return offset;
        } catch (IllegalArgumentException e) {
            throw invalidPaginationToken();
        }
    }

    private static String encodeToken(String action, String scope, int offset) {
        String value = action + ":" + scope + ":" + offset;
        return Base64.getEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String requiredString(JsonNode request,
                                         String field,
                                         int maxLength,
                                         Pattern pattern,
                                         String patternText) {
        JsonNode value = request == null ? null : request.get(field);
        if (value == null || value.isNull()) {
            throw invalidArgument("Value null at '" + lowerCamel(field)
                    + "' failed to satisfy constraint: Member must not be null");
        }
        return validatedString(value, field, 1, maxLength, pattern, patternText);
    }

    private static String optionalString(JsonNode request,
                                         String field,
                                         int minLength,
                                         int maxLength,
                                         Pattern pattern,
                                         String patternText) {
        JsonNode value = request == null ? null : request.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        return validatedString(value, field, minLength, maxLength, pattern, patternText);
    }

    private static String optionalTypedString(JsonNode request, String field) {
        JsonNode value = request == null ? null : request.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            throw invalidArgument("Value at '" + lowerCamel(field)
                    + "' failed to satisfy constraint: Member must be a string");
        }
        return value.textValue();
    }

    private static String validatedString(JsonNode node,
                                          String field,
                                          int minLength,
                                          int maxLength,
                                          Pattern pattern,
                                          String patternText) {
        String member = lowerCamel(field);
        if (!node.isTextual()) {
            throw invalidArgument("Value at '" + member
                    + "' failed to satisfy constraint: Member must be a string");
        }
        String value = node.textValue();
        if (value.length() < minLength) {
            throw invalidArgument("Value '" + value + "' at '" + member
                    + "' failed to satisfy constraint: Member must have length greater than or equal to "
                    + minLength);
        }
        if (value.length() > maxLength) {
            throw invalidArgument("Value '" + value + "' at '" + member
                    + "' failed to satisfy constraint: Member must have length less than or equal to "
                    + maxLength);
        }
        if (!pattern.matcher(value).matches()) {
            throw invalidArgument("Value '" + value + "' at '" + member
                    + "' failed to satisfy constraint: Member must satisfy regular expression pattern: "
                    + patternText);
        }
        return value;
    }

    private static String appliedLevel(JsonNode request) {
        JsonNode value = request == null ? null : request.get("QuotaAppliedAtLevel");
        if (value == null || value.isNull()) {
            return ServiceQuotaCatalog.ACCOUNT_LEVEL;
        }
        if (!value.isTextual()) {
            throw invalidArgument("Value at 'quotaAppliedAtLevel' failed to satisfy constraint: "
                    + "Member must be a string");
        }
        String appliedLevel = value.textValue();
        if (!APPLIED_LEVELS.contains(appliedLevel)) {
            throw invalidArgument("Value '" + appliedLevel + "' at 'quotaAppliedAtLevel' "
                    + "failed to satisfy constraint: Member must satisfy enum value set: "
                    + "[ACCOUNT, RESOURCE, ALL]");
        }
        return appliedLevel;
    }

    private static String lowerCamel(String field) {
        return Character.toLowerCase(field.charAt(0)) + field.substring(1);
    }

    private static boolean isAwsDefaultAction(String action) {
        return "GetAWSDefaultServiceQuota".equals(action)
                || "ListAWSDefaultServiceQuotas".equals(action);
    }

    private static AwsException noSuchResource() {
        return new AwsException("NoSuchResourceException",
                "The specified resource does not exist.", 400);
    }

    private static AwsException invalidPaginationToken() {
        return new AwsException("InvalidPaginationTokenException",
                "The pagination token is invalid.", 400);
    }

    private static AwsException invalidArgument(String detail) {
        return new AwsException("IllegalArgumentException",
                "1 validation error detected: " + detail, 400);
    }

    private record Page<T>(List<T> items, String nextToken) {}
}
