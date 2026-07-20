package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
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

    @Inject
    public IamConditionContextResolver(AwsFormRequestResolver formRequestResolver,
                                       AwsJsonRequestResolver jsonRequestResolver,
                                       KmsService kmsService,
                                       RdsService rdsService,
                                       RequestContext requestContext,
                                       ElbV2Service elbV2Service,
                                       Ec2Service ec2Service) {
        this.formRequestResolver = formRequestResolver;
        this.jsonRequestResolver = jsonRequestResolver;
        this.kmsService = kmsService;
        this.rdsService = rdsService;
        this.requestContext = requestContext;
        this.elbV2Service = elbV2Service;
        this.ec2Service = ec2Service;
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
            default -> null;
        };
    }

    private Map<String, List<String>> ec2ConditionContext(
            String action, ContainerRequestContext ctx, String region) {
        Map<String, List<String>> conditions = new LinkedHashMap<>();
        if (region != null && !region.isBlank()) {
            conditions.put("aws:RequestedRegion", List.of(region));
        }
        if ("ec2:CreateLaunchTemplate".equals(action)) {
            readLaunchTemplateRequestTags(ctx, conditions);
        } else if ("ec2:DeleteLaunchTemplate".equals(action)) {
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

    private Map<String, List<String>> iamConditionContext(String action, ContainerRequestContext ctx) {
        if (!"iam:AttachRolePolicy".equals(action) && !"iam:DetachRolePolicy".equals(action)) {
            return null;
        }
        String policyArn = formRequestResolver.firstParameter(ctx, "PolicyArn");
        return policyArn == null ? null : Map.of("iam:PolicyARN", List.of(policyArn));
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
