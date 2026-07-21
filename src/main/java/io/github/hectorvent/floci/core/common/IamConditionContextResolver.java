package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.autoscaling.AutoScalingService;
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
    private final AutoScalingService autoScalingService;

    @Inject
    public IamConditionContextResolver(AwsFormRequestResolver formRequestResolver,
                                       AutoScalingService autoScalingService) {
        this.formRequestResolver = formRequestResolver;
        this.autoScalingService = autoScalingService;
    }

    public Map<String, List<String>> resolve(String credentialScope, String action,
                                             ContainerRequestContext ctx, String region) {
        return switch (credentialScope) {
            case "s3" -> s3ConditionContext(action, ctx);
            case "iam" -> iamConditionContext(action, ctx);
            case "autoscaling" -> autoScalingConditionContext(action, ctx, region);
            default -> null;
        };
    }

    private Map<String, List<String>> autoScalingConditionContext(
            String action, ContainerRequestContext ctx, String region) {
        boolean createGroup = "autoscaling:CreateAutoScalingGroup".equals(action);
        boolean updateTags = "autoscaling:CreateOrUpdateTags".equals(action);
        boolean deleteGroup = "autoscaling:DeleteAutoScalingGroup".equals(action);
        boolean mutateGroupConfiguration = "autoscaling:UpdateAutoScalingGroup".equals(action)
                || "autoscaling:StartInstanceRefresh".equals(action)
                || "autoscaling:PutLifecycleHook".equals(action)
                || "autoscaling:DeleteLifecycleHook".equals(action)
                || "autoscaling:PutScalingPolicy".equals(action)
                || "autoscaling:DeletePolicy".equals(action);
        if (!createGroup && !updateTags && !deleteGroup && !mutateGroupConfiguration) {
            return null;
        }
        if (updateTags) {
            return autoScalingTagConditionContext(ctx, region);
        }
        Map<String, List<String>> conditions = new LinkedHashMap<>();
        if (region != null) {
            conditions.put("aws:RequestedRegion", List.of(region));
        }
        if (createGroup) {
            List<String> tagKeys = new ArrayList<>();
            readFormTags(ctx, "Tags.member", conditions, tagKeys);
            if (!tagKeys.isEmpty()) {
                conditions.put("aws:TagKeys", List.copyOf(tagKeys));
            }
        }
        if (deleteGroup || mutateGroupConfiguration) {
            addAutoScalingResourceTags(
                    formRequestResolver.firstParameter(ctx, "AutoScalingGroupName"),
                    region, conditions);
        }
        return conditions.isEmpty() ? null : conditions;
    }

    private Map<String, List<String>> autoScalingTagConditionContext(
            ContainerRequestContext ctx, String region) {
        Map<String, AutoScalingTagRequest> requests = new LinkedHashMap<>();
        for (int index = 1; ; index++) {
            String prefix = "Tags.member." + index;
            String resourceId = formRequestResolver.firstParameter(ctx, prefix + ".ResourceId");
            if (resourceId == null) {
                break;
            }
            AutoScalingTagRequest request = requests.computeIfAbsent(
                    resourceId, ignored -> new AutoScalingTagRequest());
            String tagKey = formRequestResolver.firstParameter(ctx, prefix + ".Key");
            String tagValue = formRequestResolver.firstParameter(ctx, prefix + ".Value");
            if (tagKey != null) {
                request.tagKeys().add(tagKey);
                if (tagValue != null) {
                    request.conditions().put("aws:RequestTag/" + tagKey, List.of(tagValue));
                }
            }
        }
        if (requests.isEmpty()) {
            return null;
        }

        List<AdditionalResourceCondition> additionalResources = new ArrayList<>();
        Map<String, List<String>> primaryConditions = null;
        for (Map.Entry<String, AutoScalingTagRequest> entry : requests.entrySet()) {
            AutoScalingTagRequest request = entry.getValue();
            if (!request.tagKeys().isEmpty()) {
                request.conditions().put("aws:TagKeys", List.copyOf(request.tagKeys()));
            }
            addAutoScalingResourceTags(entry.getKey(), region, request.conditions());
            if (primaryConditions == null) {
                primaryConditions = request.conditions();
            } else {
                additionalResources.add(new AdditionalResourceCondition(
                        autoScalingGroupArn(entry.getKey(), region),
                        Map.copyOf(request.conditions())));
            }
        }
        return new ResourceAwareConditionContext(primaryConditions, additionalResources);
    }

    private String autoScalingGroupArn(String name, String region) {
        if (name == null || name.isBlank()) {
            return "*";
        }
        try {
            return autoScalingService.requireAutoScalingGroup(region, name).getAutoScalingGroupArn();
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve Auto Scaling group ARN for {0}: {1}", name, e.getMessage());
            return "*";
        }
    }

    private void addAutoScalingResourceTags(
            String name, String region, Map<String, List<String>> conditions) {
        if (name == null || name.isBlank()) {
            return;
        }
        try {
            autoScalingService.requireAutoScalingGroup(region, name).getTags()
                    .forEach((key, value) ->
                            conditions.put("aws:ResourceTag/" + key, List.of(value)));
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve Auto Scaling group tags for {0}: {1}", name, e.getMessage());
        }
    }

    private void readFormTags(
            ContainerRequestContext ctx,
            String prefix,
            Map<String, List<String>> conditions,
            List<String> tagKeys) {
        for (int index = 1; ; index++) {
            String key = formRequestResolver.firstParameter(ctx, prefix + "." + index + ".Key");
            if (key == null) {
                return;
            }
            String value = formRequestResolver.firstParameter(ctx, prefix + "." + index + ".Value");
            tagKeys.add(key);
            if (value != null) {
                conditions.put("aws:RequestTag/" + key, List.of(value));
            }
        }
    }

    private record AutoScalingTagRequest(
            Map<String, List<String>> conditions, List<String> tagKeys) {
        private AutoScalingTagRequest() {
            this(new LinkedHashMap<>(), new ArrayList<>());
        }
    }

    public record AdditionalResourceCondition(
            String resourceArn, Map<String, List<String>> conditionContext) {}

    public static final class ResourceAwareConditionContext extends LinkedHashMap<String, List<String>> {
        private final List<AdditionalResourceCondition> additionalResources;

        private ResourceAwareConditionContext(
                Map<String, List<String>> primaryConditions,
                List<AdditionalResourceCondition> additionalResources) {
            super(primaryConditions == null ? Map.of() : primaryConditions);
            this.additionalResources = List.copyOf(additionalResources);
        }

        public List<AdditionalResourceCondition> additionalResources() {
            return additionalResources;
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
