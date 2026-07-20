package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.services.autoscaling.AutoScalingService;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.services.rds.RdsService;
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
    private final RdsService rdsService;
    private final RequestContext requestContext;
    private final ElbV2Service elbV2Service;
    private final Ec2Service ec2Service;
    private final AutoScalingService autoScalingService;

    @Inject
    public IamConditionContextResolver(AwsFormRequestResolver formRequestResolver,
                                       AwsJsonRequestResolver jsonRequestResolver,
                                       KmsService kmsService,
                                       RdsService rdsService,
                                       RequestContext requestContext,
                                       ElbV2Service elbV2Service,
                                       Ec2Service ec2Service,
                                       AutoScalingService autoScalingService) {
        this.formRequestResolver = formRequestResolver;
        this.jsonRequestResolver = jsonRequestResolver;
        this.kmsService = kmsService;
        this.rdsService = rdsService;
        this.requestContext = requestContext;
        this.elbV2Service = elbV2Service;
        this.ec2Service = ec2Service;
        this.autoScalingService = autoScalingService;
    }

    public Map<String, List<String>> resolve(String credentialScope, String action,
                                             ContainerRequestContext ctx, String region) {
        return switch (credentialScope) {
            case "s3" -> s3ConditionContext(action, ctx);
            case "iam" -> iamConditionContext(action, ctx);
            case "kms" -> kmsConditionContext(action, ctx, region);
            case "rds" -> rdsConditionContext(action, ctx);
            case "elasticloadbalancing" -> elbConditionContext(action, ctx);
            case "ec2" -> ec2ConditionContext(action, ctx, region);
            case "autoscaling" -> autoScalingConditionContext(action, ctx, region);
            default -> null;
        };
    }

    private Map<String, List<String>> autoScalingConditionContext(
            String action, ContainerRequestContext ctx, String region) {
        boolean createGroup = "autoscaling:CreateAutoScalingGroup".equals(action);
        boolean updateTags = "autoscaling:CreateOrUpdateTags".equals(action);
        boolean deleteGroup = "autoscaling:DeleteAutoScalingGroup".equals(action);
        boolean mutateGroupConfiguration = "autoscaling:PutLifecycleHook".equals(action)
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
            String resourceArn = formRequestResolver.firstParameter(
                    ctx, loadBalancerMutation ? "LoadBalancerArn" : "TargetGroupArn");
            if (resourceArn != null && !resourceArn.isBlank()) {
                elbV2Service.describeTags(List.of(resourceArn))
                        .getOrDefault(resourceArn, Map.of())
                        .forEach((tagKey, tagValue) ->
                                conditions.put("aws:ResourceTag/" + tagKey, List.of(tagValue)));
            }
        }
        if (createListener && formRequestResolver != null && elbV2Service != null) {
            String loadBalancerArn = formRequestResolver.firstParameter(ctx, "LoadBalancerArn");
            if (loadBalancerArn != null && !loadBalancerArn.isBlank()) {
                elbV2Service.describeTags(List.of(loadBalancerArn))
                        .getOrDefault(loadBalancerArn, Map.of())
                        .forEach((tagKey, tagValue) ->
                                conditions.put("aws:ResourceTag/" + tagKey, List.of(tagValue)));
            }
        }
        if (deleteListener && formRequestResolver != null && elbV2Service != null) {
            String listenerArn = formRequestResolver.firstParameter(ctx, "ListenerArn");
            if (listenerArn != null && !listenerArn.isBlank()) {
                elbV2Service.describeTags(List.of(listenerArn))
                        .getOrDefault(listenerArn, Map.of())
                        .forEach((tagKey, tagValue) ->
                                conditions.put("aws:ResourceTag/" + tagKey, List.of(tagValue)));
            }
        }
        return conditions.isEmpty() ? null : conditions;
    }

    private Map<String, List<String>> ec2ConditionContext(
            String action, ContainerRequestContext ctx, String region) {
        Map<String, List<String>> conditions = new LinkedHashMap<>();
        if (region != null && !region.isBlank()) {
            conditions.put("aws:RequestedRegion", List.of(region));
        }
        if ("ec2:CreateLaunchTemplate".equals(action)) {
            readLaunchTemplateRequestTags(ctx, conditions);
        } else if ("ec2:CreateLaunchTemplateVersion".equals(action)
                || "ec2:ModifyLaunchTemplate".equals(action)
                || "ec2:DeleteLaunchTemplate".equals(action)) {
            addLaunchTemplateResourceTags(ctx, region, conditions);
        } else {
            return null;
        }
        return conditions.isEmpty() ? null : conditions;
    }

    private void readLaunchTemplateRequestTags(
            ContainerRequestContext ctx, Map<String, List<String>> conditions) {
        for (int specification = 1; ; specification++) {
            String prefix = "TagSpecification." + specification;
            String resourceType = formRequestResolver.firstParameter(ctx, prefix + ".ResourceType");
            if (resourceType == null) {
                return;
            }
            if (!"launch-template".equals(resourceType)) {
                continue;
            }
            for (int tag = 1; ; tag++) {
                String tagPrefix = prefix + ".Tag." + tag;
                String key = formRequestResolver.firstParameter(ctx, tagPrefix + ".Key");
                if (key == null) {
                    break;
                }
                String value = formRequestResolver.firstParameter(ctx, tagPrefix + ".Value");
                if (value != null) {
                    conditions.put("aws:RequestTag/" + key, List.of(value));
                }
            }
        }
    }

    private void addLaunchTemplateResourceTags(
            ContainerRequestContext ctx, String region, Map<String, List<String>> conditions) {
        String id = formRequestResolver.firstParameter(ctx, "LaunchTemplateId");
        String name = formRequestResolver.firstParameter(ctx, "LaunchTemplateName");
        try {
            ec2Service.resolveLaunchTemplate(region, id, name).getTags().forEach(tag -> {
                if (tag.getKey() != null && tag.getValue() != null) {
                    conditions.put("aws:ResourceTag/" + tag.getKey(), List.of(tag.getValue()));
                }
            });
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve EC2 launch template tags for {0}: {1}",
                    id != null ? id : name, e.getMessage());
        }
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

    private Map<String, List<String>> rdsConditionContext(
            String action, ContainerRequestContext ctx) {
        Map<String, List<String>> conditions = new LinkedHashMap<>();
        readFormTags(ctx, "Tags.member", conditions);
        readFormTags(ctx, "Tags.Tag", conditions);
        readFormTags(ctx, "Tag", conditions);
        addRdsResourceTags(action, ctx, conditions);
        return conditions.isEmpty() ? null : conditions;
    }

    private void addRdsResourceTags(
            String action, ContainerRequestContext ctx, Map<String, List<String>> conditions) {
        String resourceIdentifier = switch (action) {
            case "rds:DeleteDBInstance", "rds:ModifyDBInstance", "rds:RebootDBInstance" ->
                    formRequestResolver.firstParameter(ctx, "DBInstanceIdentifier");
            case "rds:DeleteDBCluster", "rds:ModifyDBCluster" ->
                    formRequestResolver.firstParameter(ctx, "DBClusterIdentifier");
            case "rds:DeleteDBParameterGroup", "rds:ModifyDBParameterGroup" ->
                    formRequestResolver.firstParameter(ctx, "DBParameterGroupName");
            case "rds:DeleteDBSubnetGroup", "rds:ModifyDBSubnetGroup" ->
                    formRequestResolver.firstParameter(ctx, "DBSubnetGroupName");
            case "rds:AddTagsToResource", "rds:RemoveTagsFromResource" ->
                    formRequestResolver.firstParameter(ctx, "ResourceName");
            default -> null;
        };
        if (resourceIdentifier == null || resourceIdentifier.isBlank()) {
            return;
        }
        try {
            Map<String, String> tags = switch (action) {
                case "rds:DeleteDBInstance", "rds:ModifyDBInstance", "rds:RebootDBInstance" ->
                        rdsService.getDbInstance(resourceIdentifier).getTags();
                case "rds:DeleteDBCluster", "rds:ModifyDBCluster" ->
                        rdsService.getDbCluster(resourceIdentifier).getTags();
                case "rds:DeleteDBParameterGroup", "rds:ModifyDBParameterGroup" ->
                        rdsService.getDbParameterGroup(resourceIdentifier, requestContext.getRegion()).getTags();
                case "rds:DeleteDBSubnetGroup", "rds:ModifyDBSubnetGroup" ->
                        rdsService.getDbSubnetGroup(resourceIdentifier, requestContext.getRegion()).getTags();
                case "rds:AddTagsToResource", "rds:RemoveTagsFromResource" ->
                        rdsService.listTagsForResource(resourceIdentifier);
                default -> Map.of();
            };
            tags.forEach((key, value) -> {
                if (key != null && value != null) {
                    conditions.put("aws:ResourceTag/" + key, List.of(value));
                }
            });
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve RDS resource tags for {0}: {1}", action, e.getMessage());
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
