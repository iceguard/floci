package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.rds.RdsService;
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
    private final RdsService rdsService;
    private final RequestContext requestContext;

    @Inject
    public IamConditionContextResolver(AwsFormRequestResolver formRequestResolver,
                                       RdsService rdsService,
                                       RequestContext requestContext) {
        this.formRequestResolver = formRequestResolver;
        this.rdsService = rdsService;
        this.requestContext = requestContext;
    }

    public Map<String, List<String>> resolve(String credentialScope, String action,
                                             ContainerRequestContext ctx, String region) {
        return switch (credentialScope) {
            case "s3" -> s3ConditionContext(action, ctx);
            case "iam" -> iamConditionContext(action, ctx);
            case "rds" -> rdsConditionContext(action, ctx);
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
