package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.ec2.Ec2Service;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class IamConditionContextResolver {

    private static final Logger LOG = Logger.getLogger(IamConditionContextResolver.class);

    private final AwsFormRequestResolver formRequestResolver;
    private final Ec2Service ec2Service;

    @Inject
    public IamConditionContextResolver(AwsFormRequestResolver formRequestResolver,
                                       Ec2Service ec2Service) {
        this.formRequestResolver = formRequestResolver;
        this.ec2Service = ec2Service;
    }

    public Map<String, List<String>> resolve(String credentialScope, String action,
                                             ContainerRequestContext ctx, String region) {
        return switch (credentialScope) {
            case "s3" -> s3ConditionContext(action, ctx);
            case "iam" -> iamConditionContext(action, ctx);
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
        } else if ("ec2:CreateVpcEndpoint".equals(action)) {
            readEc2RequestTags(ctx, "vpc-endpoint", conditions);
        } else if ("ec2:ModifyVpcEndpoint".equals(action)
                || "ec2:DeleteVpcEndpoints".equals(action)) {
            addVpcEndpointResourceTags(ctx, region, conditions);
        } else if ("ec2:CreateTags".equals(action) && isVpcEndpointResource(ctx)) {
            readFormTags(ctx, "Tag", conditions);
            addVpcEndpointResourceTags(ctx, region, conditions);
        } else if ("ec2:CreateLaunchTemplateVersion".equals(action)
                || "ec2:ModifyLaunchTemplate".equals(action)
                || "ec2:DeleteLaunchTemplate".equals(action)) {
            addLaunchTemplateResourceTags(ctx, region, conditions);
        } else {
            return null;
        }
        return conditions.isEmpty() ? null : conditions;
    }

    private boolean isVpcEndpointResource(ContainerRequestContext ctx) {
        String resourceId = formRequestResolver.firstParameter(ctx, "ResourceId.1");
        return resourceId != null && resourceId.startsWith("vpce-");
    }

    private void readEc2RequestTags(
            ContainerRequestContext ctx,
            String expectedResourceType,
            Map<String, List<String>> conditions) {
        for (int specification = 1; ; specification++) {
            String prefix = "TagSpecification." + specification;
            String resourceType = formRequestResolver.firstParameter(ctx, prefix + ".ResourceType");
            if (resourceType == null) {
                return;
            }
            if (!expectedResourceType.equals(resourceType)) {
                continue;
            }
            readFormTags(ctx, prefix + ".Tag", conditions);
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

    private void addVpcEndpointResourceTags(
            ContainerRequestContext ctx,
            String region,
            Map<String, List<String>> conditions) {
        String endpointId = formRequestResolver.firstParameter(ctx, "VpcEndpointId");
        if (endpointId == null) {
            endpointId = formRequestResolver.firstParameter(ctx, "VpcEndpointId.1");
        }
        if (endpointId == null) {
            endpointId = formRequestResolver.firstParameter(ctx, "ResourceId.1");
        }
        if (endpointId == null || !endpointId.startsWith("vpce-")) {
            return;
        }
        try {
            ec2Service.describeVpcEndpoints(region, List.of(endpointId), Map.of())
                    .getFirst()
                    .getTags()
                    .forEach(tag -> {
                        if (tag.getKey() != null && tag.getValue() != null) {
                            conditions.put(
                                    "aws:ResourceTag/" + tag.getKey(),
                                    List.of(tag.getValue()));
                        }
                    });
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve EC2 VPC endpoint tags for {0}: {1}",
                    endpointId, e.getMessage());
        }
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
