package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
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
    private final ElbV2Service elbV2Service;

    @Inject
    public IamConditionContextResolver(AwsFormRequestResolver formRequestResolver,
                                       ElbV2Service elbV2Service) {
        this.formRequestResolver = formRequestResolver;
        this.elbV2Service = elbV2Service;
    }

    public Map<String, List<String>> resolve(String credentialScope, String action,
                                             ContainerRequestContext ctx, String region) {
        return switch (credentialScope) {
            case "s3" -> s3ConditionContext(action, ctx);
            case "iam" -> iamConditionContext(action, ctx);
            case "elasticloadbalancing" -> elbConditionContext(action, ctx);
            default -> null;
        };
    }

    private Map<String, List<String>> elbConditionContext(
            String action, ContainerRequestContext ctx) {
        boolean create = "elasticloadbalancing:CreateLoadBalancer".equals(action)
                || "elasticloadbalancing:CreateTargetGroup".equals(action)
                || "elasticloadbalancing:CreateListener".equals(action);
        boolean createListener = "elasticloadbalancing:CreateListener".equals(action);
        boolean deleteListener = "elasticloadbalancing:DeleteListener".equals(action);
        boolean loadBalancerMutation = "elasticloadbalancing:DeleteLoadBalancer".equals(action);
        boolean targetGroupMutation = switch (action) {
            case "elasticloadbalancing:DeleteTargetGroup",
                    "elasticloadbalancing:DeregisterTargets",
                    "elasticloadbalancing:ModifyTargetGroup",
                    "elasticloadbalancing:ModifyTargetGroupAttributes",
                    "elasticloadbalancing:RegisterTargets" -> true;
            default -> false;
        };
        if (!create && !deleteListener && !loadBalancerMutation && !targetGroupMutation) {
            return null;
        }

        Map<String, List<String>> conditions = new LinkedHashMap<>();
        if (create) {
            readFormTags(ctx, "Tags.member", conditions);
        }
        if (loadBalancerMutation || targetGroupMutation) {
            addElbResourceTags(
                    ctx, loadBalancerMutation ? "LoadBalancerArn" : "TargetGroupArn", conditions);
        }
        if (createListener) {
            addElbResourceTags(ctx, "LoadBalancerArn", conditions);
        }
        if (deleteListener) {
            addElbResourceTags(ctx, "ListenerArn", conditions);
        }
        return conditions.isEmpty() ? null : conditions;
    }

    private void addElbResourceTags(
            ContainerRequestContext ctx, String parameter, Map<String, List<String>> conditions) {
        String resourceArn = formRequestResolver.firstParameter(ctx, parameter);
        if (resourceArn != null && !resourceArn.isBlank()) {
            elbV2Service.describeTags(List.of(resourceArn))
                    .getOrDefault(resourceArn, Map.of())
                    .forEach((tagKey, tagValue) ->
                            conditions.put("aws:ResourceTag/" + tagKey, List.of(tagValue)));
        }
    }

    private void readFormTags(
            ContainerRequestContext ctx,
            String prefix,
            Map<String, List<String>> conditions) {
        for (int index = 1; ; index++) {
            String key = formRequestResolver.firstParameter(ctx, prefix + "." + index + ".Key");
            if (key == null) {
                return;
            }
            String value = formRequestResolver.firstParameter(ctx, prefix + "." + index + ".Value");
            if (value != null) {
                conditions.put("aws:RequestTag/" + key, List.of(value));
            }
        }
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
