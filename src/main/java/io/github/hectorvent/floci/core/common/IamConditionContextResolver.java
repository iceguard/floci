package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.services.kms.KmsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class IamConditionContextResolver {

    private static final Logger LOG = Logger.getLogger(IamConditionContextResolver.class);

    private final AwsFormRequestResolver formRequestResolver;
    private final AwsJsonRequestResolver jsonRequestResolver;
    private final KmsService kmsService;

    @Inject
    public IamConditionContextResolver(AwsFormRequestResolver formRequestResolver,
                                       AwsJsonRequestResolver jsonRequestResolver,
                                       KmsService kmsService) {
        this.formRequestResolver = formRequestResolver;
        this.jsonRequestResolver = jsonRequestResolver;
        this.kmsService = kmsService;
    }

    public Map<String, List<String>> resolve(String credentialScope, String action,
                                             ContainerRequestContext ctx, String region) {
        return switch (credentialScope) {
            case "s3" -> s3ConditionContext(action, ctx);
            case "iam" -> iamConditionContext(action, ctx);
            case "kms" -> kmsConditionContext(action, ctx, region);
            default -> null;
        };
    }

    private Map<String, List<String>> iamConditionContext(String action, ContainerRequestContext ctx) {
        if (!"iam:AttachRolePolicy".equals(action) && !"iam:DetachRolePolicy".equals(action)) {
            return null;
        }
        String policyArn = formRequestResolver.firstParameter(ctx, "PolicyArn");
        return policyArn == null ? null : Map.of("iam:PolicyARN", List.of(policyArn));
    }

    private Map<String, List<String>> kmsConditionContext(
            String action, ContainerRequestContext ctx, String region) {
        Map<String, List<String>> conditions = new LinkedHashMap<>();
        if (region != null) {
            conditions.put("aws:RequestedRegion", List.of(region));
        }

        JsonNode request = jsonRequestResolver.body(ctx);
        if (request == null) {
            return conditions.isEmpty() ? null : conditions;
        }

        List<String> tagKeys = new ArrayList<>();
        request.path("Tags").forEach(tag -> {
            String tagKey = tag.path("TagKey").asText(null);
            String tagValue = tag.path("TagValue").asText(null);
            if (tagKey != null) {
                tagKeys.add(tagKey);
            }
            if (tagKey != null && tagValue != null) {
                conditions.put("aws:RequestTag/" + tagKey, List.of(tagValue));
            }
        });
        if (!tagKeys.isEmpty()) {
            conditions.put("aws:TagKeys", List.copyOf(tagKeys));
        }

        String keyId = "kms:CreateAlias".equals(action)
                ? request.path("TargetKeyId").asText(null)
                : request.path("KeyId").asText(null);
        if (keyId != null && region != null) {
            try {
                kmsService.describeKey(keyId, region).getTags().forEach(
                        (tagKey, tagValue) ->
                                conditions.put("aws:ResourceTag/" + tagKey, List.of(tagValue)));
            } catch (AwsException e) {
                LOG.debugv("Unable to resolve KMS resource tags for {0}: {1}", keyId, e.getMessage());
            }
        }
        return conditions;
    }

    private Map<String, List<String>> s3ConditionContext(String action, ContainerRequestContext ctx) {
        return switch (action) {
            case "s3:ListBucket" -> s3BucketListConditionContext(ctx.getUriInfo().getQueryParameters());
            default -> null;
        };
    }

    Map<String, List<String>> s3BucketListConditionContext(
            MultivaluedMap<String, String> queryParameters) {
        Map<String, List<String>> conditions = new LinkedHashMap<>();
        addQueryCondition(conditions, "s3:prefix", queryParameters, "prefix");
        addQueryCondition(conditions, "s3:delimiter", queryParameters, "delimiter");
        addQueryCondition(conditions, "s3:max-keys", queryParameters, "max-keys");
        return conditions.isEmpty() ? null : conditions;
    }

    private static void addQueryCondition(Map<String, List<String>> conditions, String conditionKey,
                                          MultivaluedMap<String, String> queryParameters, String queryParameter) {
        String value = queryParameters.getFirst(queryParameter);
        if (value != null) {
            conditions.put(conditionKey, List.of(value));
        }
    }
}
