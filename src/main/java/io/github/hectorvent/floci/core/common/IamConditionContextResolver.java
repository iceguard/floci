package io.github.hectorvent.floci.core.common;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedMap;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class IamConditionContextResolver {

    private final AwsFormRequestResolver formRequestResolver;

    @Inject
    public IamConditionContextResolver(AwsFormRequestResolver formRequestResolver) {
        this.formRequestResolver = formRequestResolver;
    }

    public Map<String, List<String>> resolve(String credentialScope, String action,
                                             ContainerRequestContext ctx, String region) {
        return switch (credentialScope) {
            case "s3" -> s3ConditionContext(action, ctx);
            case "iam" -> iamConditionContext(action, ctx);
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
