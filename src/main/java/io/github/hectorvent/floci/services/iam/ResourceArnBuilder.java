package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsFormRequestResolver;
import io.github.hectorvent.floci.core.common.AwsJsonRequestResolver;
import io.github.hectorvent.floci.core.common.IamConditionContextResolver.ResourceAwareConditionContext;
import io.github.hectorvent.floci.services.autoscaling.AutoScalingService;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import io.github.hectorvent.floci.services.ec2.model.Tag;
import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Constructs the target resource ARN for a request so the policy evaluator
 * can match it against Resource patterns in policy documents.
 *
 * Returns {@code *} when the resource cannot be determined, which matches
 * permissive wildcard policies.
 */
@ApplicationScoped
public class ResourceArnBuilder {

    private static final Logger LOG = Logger.getLogger(ResourceArnBuilder.class);

    private final IamService iamService;
    private final AwsFormRequestResolver formRequestResolver;
    private final ObjectMapper objectMapper;
    private final SecretsManagerService secretsManagerService;
    private final AwsJsonRequestResolver jsonRequestResolver;
    private final KmsService kmsService;
    private final Ec2Service ec2Service;
    private final AutoScalingService autoScalingService;

    @Inject
    public ResourceArnBuilder(IamService iamService, AwsFormRequestResolver formRequestResolver,
                              ObjectMapper objectMapper, SecretsManagerService secretsManagerService,
                              AwsJsonRequestResolver jsonRequestResolver, KmsService kmsService,
                              Ec2Service ec2Service, AutoScalingService autoScalingService) {
        this.iamService = iamService;
        this.formRequestResolver = formRequestResolver;
        this.objectMapper = objectMapper;
        this.secretsManagerService = secretsManagerService;
        this.jsonRequestResolver = jsonRequestResolver;
        this.kmsService = kmsService;
        this.ec2Service = ec2Service;
        this.autoScalingService = autoScalingService;
    }

    public String build(String credentialScope, ContainerRequestContext ctx,
                        String region, String accountId) {
        String path = ctx.getUriInfo().getPath();
        return switch (credentialScope) {
            case "s3"             -> buildS3Arn(path);
            case "lambda"         -> buildLambdaArn(path, region, accountId);
            case "sqs"            -> buildSqsArn(ctx, region, accountId);
            case "sns"            -> buildSnsArn(ctx, region, accountId);
            case "dynamodb"       -> buildDynamoDbArn(ctx, region, accountId);
            case "kinesis"        -> buildKinesisArn(ctx, region, accountId);
            case "secretsmanager" -> buildSecretsManagerArn(ctx, region, accountId);
            case "ssm"            -> buildSsmArn(ctx, region, accountId);
            case "kms"            -> buildKmsArn(ctx, path, region, accountId);
            case "iam"            -> buildIamArn(ctx, accountId);
            case "rds"            -> buildRdsArn(ctx, region, accountId);
            case "elasticloadbalancing" -> buildElbArn(ctx, region, accountId);
            case "ec2"            -> buildEc2Arn(ctx, region, accountId);
            case "autoscaling"    -> buildAutoScalingArn(ctx, region, accountId);
            default               -> "*";
        };
    }

    public List<AuthorizationRequest> resourceAuthorizations(
            String credentialScope, String action, ContainerRequestContext ctx,
            String region, String accountId) {
        if ("ec2".equals(credentialScope)
                && ("ec2:DeleteVpcEndpoints".equals(action)
                        || "ec2:CreateTags".equals(action))) {
            List<String> endpointIds = indexedFormParameters(
                    ctx,
                    "ec2:DeleteVpcEndpoints".equals(action)
                            ? "VpcEndpointId"
                            : "ResourceId");
            if (!endpointIds.isEmpty()
                    && endpointIds.stream().allMatch(id -> id.startsWith("vpce-"))) {
                Map<String, List<String>> requestTags =
                        "ec2:CreateTags".equals(action) ? ec2RequestTags(ctx) : Map.of();
                return endpointIds.stream()
                        .map(endpointId -> new AuthorizationRequest(
                                action,
                                vpcEndpointArn(endpointId, region, accountId),
                                vpcEndpointConditionContext(endpointId, region, requestTags)))
                        .toList();
            }
        }
        if ("iam".equals(credentialScope)
                && ("iam:AddRoleToInstanceProfile".equals(action)
                        || "iam:RemoveRoleFromInstanceProfile".equals(action))) {
            return List.of(
                    new AuthorizationRequest(action, existingRoleArn(ctx, accountId), null),
                    new AuthorizationRequest(action, existingInstanceProfileArn(ctx, accountId), null));
        }
        if (!"ssm".equals(credentialScope) || !"ssm:SendCommand".equals(action)) {
            return List.of();
        }
        JsonNode request = jsonRequestResolver.body(ctx);
        if (request == null) {
            return List.of();
        }

        List<AuthorizationRequest> authorizations = new ArrayList<>();
        for (String targetId : resolveSsmTargetIds(request, region)) {
            if (targetId.startsWith("i-")) {
                authorizations.add(new AuthorizationRequest(
                        action,
                        AwsArnUtils.Arn.of("ec2", region, accountId, "instance/" + targetId).toString(),
                        ssmTargetTagContext(ec2Service.findInstanceById(targetId), region)));
            } else if (targetId.startsWith("mi-")) {
                authorizations.add(new AuthorizationRequest(
                        action,
                        AwsArnUtils.Arn.of(
                                "ssm", region, accountId, "managed-instance/" + targetId).toString(),
                        null));
            }
        }

        String documentName = request.path("DocumentName").asText(null);
        if (documentName != null && !documentName.isBlank()) {
            String documentArn = documentName.startsWith("arn:")
                    ? documentName
                    : AwsArnUtils.Arn.of(
                            "ssm", region, awsOwnedDocument(documentName) ? "" : accountId,
                            "document/" + documentName).toString();
            authorizations.add(new AuthorizationRequest(action, documentArn, null));
        }
        return List.copyOf(authorizations);
    }

    private List<String> indexedFormParameters(
            ContainerRequestContext ctx, String prefix) {
        List<String> values = new ArrayList<>();
        for (int index = 1; ; index++) {
            String value = formRequestResolver.firstParameter(
                    ctx, prefix + "." + index);
            if (value == null) {
                return values;
            }
            values.add(value);
        }
    }

    private Map<String, List<String>> ec2RequestTags(ContainerRequestContext ctx) {
        Map<String, List<String>> conditions = new LinkedHashMap<>();
        for (int index = 1; ; index++) {
            String key = formRequestResolver.firstParameter(
                    ctx, "Tag." + index + ".Key");
            if (key == null) {
                return conditions;
            }
            String value = formRequestResolver.firstParameter(
                    ctx, "Tag." + index + ".Value");
            if (value != null) {
                conditions.put("aws:RequestTag/" + key, List.of(value));
            }
        }
    }

    private Map<String, List<String>> vpcEndpointConditionContext(
            String endpointId,
            String region,
            Map<String, List<String>> requestTags) {
        Map<String, List<String>> conditions = new LinkedHashMap<>(requestTags);
        if (region != null && !region.isBlank()) {
            conditions.put("aws:RequestedRegion", List.of(region));
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
        return conditions.isEmpty() ? null : Map.copyOf(conditions);
    }

    private Set<String> resolveSsmTargetIds(JsonNode request, String region) {
        Set<String> targetIds = new LinkedHashSet<>();
        request.path("InstanceIds").forEach(node -> addTargetId(targetIds, node.asText(null)));
        request.path("Targets").forEach(target -> {
            String key = target.path("Key").asText("");
            List<String> values = new ArrayList<>();
            target.path("Values").forEach(value -> values.add(value.asText()));
            if ("InstanceIds".equals(key)) {
                values.forEach(value -> addTargetId(targetIds, value));
            } else if (key.startsWith("tag:") && !values.isEmpty()) {
                Map<String, List<String>> filters = Map.of(key, values);
                for (Reservation reservation : ec2Service.describeInstances(region, List.of(), filters)) {
                    reservation.getInstances().forEach(
                            instance -> addTargetId(targetIds, instance.getInstanceId()));
                }
            }
        });
        return targetIds;
    }

    private static void addTargetId(Set<String> targetIds, String targetId) {
        if (targetId != null && (targetId.startsWith("i-") || targetId.startsWith("mi-"))) {
            targetIds.add(targetId);
        }
    }

    private static Map<String, List<String>> ssmTargetTagContext(Instance instance, String region) {
        if (instance == null || !region.equals(instance.getRegion())
                || instance.getTags() == null || instance.getTags().isEmpty()) {
            return null;
        }
        Map<String, List<String>> conditions = new LinkedHashMap<>();
        for (Tag tag : instance.getTags()) {
            if (tag.getKey() != null && tag.getValue() != null) {
                conditions.put("ssm:resourceTag/" + tag.getKey(), List.of(tag.getValue()));
                conditions.put("aws:ResourceTag/" + tag.getKey(), List.of(tag.getValue()));
            }
        }
        return conditions.isEmpty() ? null : Map.copyOf(conditions);
    }

    private static boolean awsOwnedDocument(String documentName) {
        return documentName.startsWith("AWS-") || documentName.startsWith("Amazon-");
    }

    public List<String> additionalResources(String credentialScope, ContainerRequestContext ctx,
                                            String region, String accountId) {
        if (!"kms".equals(credentialScope) || !isKmsAction(ctx, "CreateAlias")) {
            return List.of();
        }
        String targetKeyId = jsonRequestResolver.firstTextField(ctx, "TargetKeyId");
        return targetKeyId == null || targetKeyId.isBlank()
                ? List.of()
                : List.of(resolveKmsKeyArn(targetKeyId, region, accountId));
    }

    public List<AuthorizationRequest> additionalAuthorizations(
            String action, String primaryResource, Map<String, List<String>> conditionContext) {
        if ("autoscaling:CreateOrUpdateTags".equals(action)
                && conditionContext instanceof ResourceAwareConditionContext resourceAware) {
            return resourceAware.additionalResources().stream()
                    .map(resource -> new AuthorizationRequest(
                            action, resource.resourceArn(), resource.conditionContext()))
                    .toList();
        }
        if (("ec2:CreateLaunchTemplate".equals(action)
                || "ec2:CreateVpcEndpoint".equals(action))
                && hasRequestTags(conditionContext)) {
            Map<String, List<String>> createTagsContext = new LinkedHashMap<>(conditionContext);
            createTagsContext.put(
                    "ec2:CreateAction",
                    List.of("ec2:CreateVpcEndpoint".equals(action)
                            ? "CreateVpcEndpoint"
                            : "CreateLaunchTemplate"));
            return List.of(new AuthorizationRequest(
                    "ec2:CreateTags", primaryResource, Map.copyOf(createTagsContext)));
        }
        if (!hasRequestTags(conditionContext)) {
            return List.of();
        }
        Map<String, List<String>> addTagsContext = new LinkedHashMap<>(conditionContext);
        if ("elasticloadbalancing:CreateTargetGroup".equals(action)) {
            addTagsContext.put("elasticloadbalancing:CreateAction", List.of("CreateTargetGroup"));
            return List.of(new AuthorizationRequest(
                    "elasticloadbalancing:AddTags", primaryResource, Map.copyOf(addTagsContext)));
        }
        if ("elasticloadbalancing:CreateListener".equals(action)) {
            addTagsContext.put("elasticloadbalancing:CreateAction", List.of("CreateListener"));
            return List.of(new AuthorizationRequest(
                    "elasticloadbalancing:AddTags",
                    futureListenerArn(primaryResource),
                    Map.copyOf(addTagsContext)));
        }
        return List.of();
    }

    private static boolean hasRequestTags(Map<String, List<String>> conditionContext) {
        return conditionContext != null && conditionContext.keySet().stream()
                .anyMatch(key -> key.regionMatches(true, 0, "aws:RequestTag/", 0, 15));
    }

    public record AuthorizationRequest(
            String action, String resource, Map<String, List<String>> conditionContext) {}

    // ── S3 ──────────────────────────────────────────────────────────────────────
    private String buildS3Arn(String path) {
        // path: /bucket or /bucket/key
        String stripped = path.startsWith("/") ? path.substring(1) : path;
        if (stripped.isEmpty()) {
            return AwsArnUtils.Arn.of("s3", "", "", "*").toString();
        }
        int slash = stripped.indexOf('/');
        if (slash < 0) {
            return AwsArnUtils.Arn.of("s3", "", "", stripped).toString();
        }
        return AwsArnUtils.Arn.of("s3", "", "", stripped).toString();
    }

    // ── Lambda ──────────────────────────────────────────────────────────────────
    private String buildLambdaArn(String path, String region, String accountId) {
        // path: /2015-03-31/functions/name or similar
        String name = extractSegmentAfter(path, "functions");
        if (name == null) return "*";
        // strip qualifier if present
        int colon = name.indexOf(':');
        if (colon > 0) name = name.substring(0, colon);
        return AwsArnUtils.Arn.of("lambda", region, accountId, "function:" + name).toString();
    }

    // ── SQS ─────────────────────────────────────────────────────────────────────
    private String buildSqsArn(ContainerRequestContext ctx, String region, String accountId) {
        String queueUrl = ctx.getUriInfo().getQueryParameters().getFirst("QueueUrl");
        if (queueUrl == null) {
            // Try form param for Query-protocol
            queueUrl = firstFormParam(ctx, "QueueUrl");
        }
        if (queueUrl != null) {
            String queueName = queueUrl.substring(queueUrl.lastIndexOf('/') + 1);
            return AwsArnUtils.Arn.of("sqs", region, accountId, queueName).toString();
        }
        return AwsArnUtils.Arn.of("sqs", region, accountId, "*").toString();
    }

    // ── SNS ─────────────────────────────────────────────────────────────────────
    private String buildSnsArn(ContainerRequestContext ctx, String region, String accountId) {
        String topicArn = firstFormParam(ctx, "TopicArn");
        return topicArn != null ? topicArn : AwsArnUtils.Arn.of("sns", region, accountId, "*").toString();
    }

    // ── DynamoDB ─────────────────────────────────────────────────────────────────
    private String buildDynamoDbArn(ContainerRequestContext ctx, String region, String accountId) {
        // TableName comes in the JSON body; use wildcard since we don't parse the body here
        return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/*").toString();
    }

    // ── Kinesis ──────────────────────────────────────────────────────────────────
    private String buildKinesisArn(ContainerRequestContext ctx, String region, String accountId) {
        return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/*").toString();
    }

    // ── Secrets Manager ──────────────────────────────────────────────────────────
    private String buildSecretsManagerArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode request = readJsonRequest(ctx);
        String secretName = textField(request, "Name");
        if (secretName != null && !secretName.isBlank()) {
            return AwsArnUtils.Arn.of(
                    "secretsmanager", region, accountId, "secret:" + secretName + "-000000").toString();
        }

        String secretId = textField(request, "SecretId");
        if (secretId != null && !secretId.isBlank()) {
            try {
                return secretsManagerService.describeSecret(secretId, region).getArn();
            } catch (AwsException e) {
                LOG.debugv("Unable to resolve Secrets Manager resource {0}: {1}", secretId, e.getMessage());
                if (secretId.startsWith("arn:")) {
                    return secretId;
                }
                return AwsArnUtils.Arn.of(
                        "secretsmanager", region, accountId, "secret:" + secretId).toString();
            }
        }
        return AwsArnUtils.Arn.of("secretsmanager", region, accountId, "secret:*").toString();
    }

    // ── SSM ──────────────────────────────────────────────────────────────────────
    private String buildSsmArn(ContainerRequestContext ctx, String region, String accountId) {
        return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/*").toString();
    }

    // ── KMS ──────────────────────────────────────────────────────────────────────
    private String buildKmsArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        if (isKmsAction(ctx, "CreateKey")) {
            return "*";
        }
        if (isKmsAction(ctx, "CreateAlias")) {
            String aliasName = jsonRequestResolver.firstTextField(ctx, "AliasName");
            return aliasName == null || aliasName.isBlank()
                    ? AwsArnUtils.Arn.of("kms", region, accountId, "alias/*").toString()
                    : AwsArnUtils.Arn.of("kms", region, accountId, aliasName).toString();
        }
        String requestedKeyId = jsonRequestResolver.firstTextField(ctx, "KeyId");
        if (requestedKeyId != null && !requestedKeyId.isBlank()) {
            return resolveKmsKeyArn(requestedKeyId, region, accountId);
        }
        String keyId = extractSegmentAfter(path, "keys");
        if (keyId == null) return AwsArnUtils.Arn.of("kms", region, accountId, "key/*").toString();
        return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyId).toString();
    }

    private boolean isKmsAction(ContainerRequestContext ctx, String action) {
        String target = ctx.getHeaderString("X-Amz-Target");
        return target != null && target.endsWith("." + action);
    }

    private String resolveKmsKeyArn(String keyId, String region, String accountId) {
        try {
            return kmsService.describeKey(keyId, region).getArn();
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve KMS key resource {0}: {1}", keyId, e.getMessage());
            if (keyId.startsWith("arn:")) {
                return keyId;
            }
            return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyId).toString();
        }
    }

    // ── IAM ─────────────────────────────────────────────────────────────────────
    private String buildIamArn(ContainerRequestContext ctx, String accountId) {
        String action = formRequestResolver.firstParameter(ctx, "Action");
        return switch (action == null ? "" : action) {
            case "CreateRole" -> requestedRoleArn(ctx, accountId);
            case "DeleteRole" -> existingRoleArn(ctx, accountId);
            case "CreateInstanceProfile" -> requestedInstanceProfileArn(ctx, accountId);
            case "DeleteInstanceProfile" -> existingInstanceProfileArn(ctx, accountId);
            case "AttachRolePolicy", "DetachRolePolicy", "PutRolePolicy", "DeleteRolePolicy" ->
                    existingRoleArn(ctx, accountId);
            default -> "*";
        };
    }

    private String requestedRoleArn(ContainerRequestContext ctx, String accountId) {
        String roleName = formRequestResolver.firstParameter(ctx, "RoleName");
        if (roleName == null || roleName.isBlank()) {
            return "*";
        }
        String path = formRequestResolver.firstParameter(ctx, "Path");
        String normalizedPath = path == null || path.isBlank() ? "/" : path;
        if (!normalizedPath.startsWith("/")) {
            normalizedPath = "/" + normalizedPath;
        }
        if (!normalizedPath.endsWith("/")) {
            normalizedPath += "/";
        }
        return AwsArnUtils.Arn.of("iam", "", accountId, "role" + normalizedPath + roleName).toString();
    }

    private String requestedInstanceProfileArn(ContainerRequestContext ctx, String accountId) {
        String instanceProfileName = formRequestResolver.firstParameter(ctx, "InstanceProfileName");
        if (instanceProfileName == null || instanceProfileName.isBlank()) {
            return "*";
        }
        String path = formRequestResolver.firstParameter(ctx, "Path");
        String normalizedPath = path == null || path.isBlank() ? "/" : path;
        if (!normalizedPath.startsWith("/")) {
            normalizedPath = "/" + normalizedPath;
        }
        if (!normalizedPath.endsWith("/")) {
            normalizedPath += "/";
        }
        return AwsArnUtils.Arn.of(
                "iam", "", accountId, "instance-profile" + normalizedPath + instanceProfileName).toString();
    }

    private String existingRoleArn(ContainerRequestContext ctx, String accountId) {
        String roleName = formRequestResolver.firstParameter(ctx, "RoleName");
        if (roleName == null || roleName.isBlank()) {
            return "*";
        }
        try {
            return iamService.getRole(roleName).getArn();
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve IAM role resource {0}: {1}", roleName, e.getMessage());
            return AwsArnUtils.Arn.of("iam", "", accountId, "role/" + roleName).toString();
        }
    }

    private String existingInstanceProfileArn(ContainerRequestContext ctx, String accountId) {
        String instanceProfileName = formRequestResolver.firstParameter(ctx, "InstanceProfileName");
        if (instanceProfileName == null || instanceProfileName.isBlank()) {
            return "*";
        }
        try {
            return iamService.getInstanceProfile(instanceProfileName).getArn();
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve IAM instance profile resource {0}: {1}",
                    instanceProfileName, e.getMessage());
            return AwsArnUtils.Arn.of(
                    "iam", "", accountId, "instance-profile/" + instanceProfileName).toString();
        }
    }

    // ── RDS ─────────────────────────────────────────────────────────────────────
    private String buildRdsArn(ContainerRequestContext ctx, String region, String accountId) {
        String action = formRequestResolver.firstParameter(ctx, "Action");
        if (action == null) {
            return "*";
        }
        if ("AddTagsToResource".equals(action)
                || "ListTagsForResource".equals(action)
                || "RemoveTagsFromResource".equals(action)) {
            String resourceName = formRequestResolver.firstParameter(ctx, "ResourceName");
            return resourceName == null || resourceName.isBlank() ? "*" : resourceName;
        }
        return switch (action) {
            case "CreateDBInstance", "DeleteDBInstance", "ModifyDBInstance", "RebootDBInstance" ->
                    requestedRdsArn(ctx, region, accountId, "db", "DBInstanceIdentifier");
            case "CreateDBParameterGroup", "DeleteDBParameterGroup", "ModifyDBParameterGroup" ->
                    requestedRdsArn(ctx, region, accountId, "pg", "DBParameterGroupName");
            case "CreateDBSubnetGroup", "DeleteDBSubnetGroup", "ModifyDBSubnetGroup" ->
                    requestedRdsArn(ctx, region, accountId, "subgrp", "DBSubnetGroupName");
            case "CreateDBCluster", "DeleteDBCluster", "ModifyDBCluster" ->
                    requestedRdsArn(ctx, region, accountId, "cluster", "DBClusterIdentifier");
            case "CreateDBClusterParameterGroup", "DeleteDBClusterParameterGroup",
                    "ModifyDBClusterParameterGroup" -> requestedRdsArn(
                    ctx, region, accountId, "cluster-pg", "DBClusterParameterGroupName");
            default -> "*";
        };
    }

    private String requestedRdsArn(
            ContainerRequestContext ctx,
            String region,
            String accountId,
            String resourceType,
            String nameParameter) {
        String name = formRequestResolver.firstParameter(ctx, nameParameter);
        if (name == null || name.isBlank()) {
            return "*";
        }
        return AwsArnUtils.Arn.of("rds", region, accountId, resourceType + ":" + name).toString();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private String buildEc2Arn(ContainerRequestContext ctx, String region, String accountId) {
        String action = formRequestResolver.firstParameter(ctx, "Action");
        if ("CreateLaunchTemplate".equals(action)) {
            return AwsArnUtils.Arn.of("ec2", region, accountId,
                    "launch-template/lt-00000000000000000").toString();
        }
        if ("CreateVpcEndpoint".equals(action)) {
            return vpcEndpointArn("vpce-00000000000000000", region, accountId);
        }
        if ("ModifyVpcEndpoint".equals(action)) {
            return vpcEndpointArn(
                    formRequestResolver.firstParameter(ctx, "VpcEndpointId"),
                    region,
                    accountId);
        }
        if ("DeleteVpcEndpoints".equals(action)) {
            return vpcEndpointArn(
                    formRequestResolver.firstParameter(ctx, "VpcEndpointId.1"),
                    region,
                    accountId);
        }
        if ("CreateTags".equals(action)) {
            String resourceId = formRequestResolver.firstParameter(ctx, "ResourceId.1");
            if (resourceId != null && resourceId.startsWith("vpce-")) {
                return vpcEndpointArn(resourceId, region, accountId);
            }
        }
        if (!"CreateLaunchTemplateVersion".equals(action)
                && !"ModifyLaunchTemplate".equals(action)
                && !"DeleteLaunchTemplate".equals(action)) {
            return "*";
        }
        String id = formRequestResolver.firstParameter(ctx, "LaunchTemplateId");
        String name = formRequestResolver.firstParameter(ctx, "LaunchTemplateName");
        try {
            String resolvedId = ec2Service.resolveLaunchTemplate(region, id, name).getLaunchTemplateId();
            return AwsArnUtils.Arn.of(
                    "ec2", region, accountId, "launch-template/" + resolvedId).toString();
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve EC2 launch template resource {0}: {1}",
                    id != null ? id : name, e.getMessage());
            return id == null || id.isBlank()
                    ? "*"
                    : AwsArnUtils.Arn.of(
                            "ec2", region, accountId, "launch-template/" + id).toString();
        }
    }

    private static String vpcEndpointArn(String endpointId, String region, String accountId) {
        return endpointId == null || endpointId.isBlank()
                ? "*"
                : AwsArnUtils.Arn.of(
                        "ec2", region, accountId, "vpc-endpoint/" + endpointId).toString();
    }

    private String buildElbArn(ContainerRequestContext ctx, String region, String accountId) {
        String action = formRequestResolver.firstParameter(ctx, "Action");
        return switch (action == null ? "" : action) {
            case "CreateLoadBalancer" -> futureLoadBalancerArn(ctx, region, accountId);
            case "CreateTargetGroup" -> futureTargetGroupArn(ctx, region, accountId);
            case "CreateListener" -> exactFormResource(ctx, "LoadBalancerArn");
            case "DeleteListener" -> exactFormResource(ctx, "ListenerArn");
            case "DeleteLoadBalancer" -> exactFormResource(ctx, "LoadBalancerArn");
            case "DeleteTargetGroup", "DeregisterTargets", "ModifyTargetGroup",
                    "ModifyTargetGroupAttributes", "RegisterTargets" ->
                    exactFormResource(ctx, "TargetGroupArn");
            default -> "*";
        };
    }

    private String futureLoadBalancerArn(ContainerRequestContext ctx, String region, String accountId) {
        String name = formRequestResolver.firstParameter(ctx, "Name");
        if (name == null || name.isBlank()) {
            return "*";
        }
        String loadBalancerType = formRequestResolver.firstParameter(ctx, "Type");
        String resourceType = switch (loadBalancerType == null ? "" : loadBalancerType) {
            case "network" -> "net";
            case "gateway" -> "gwy";
            default -> "app";
        };
        return AwsArnUtils.Arn.of("elasticloadbalancing", region, accountId,
                "loadbalancer/" + resourceType + "/" + name + "/0000000000000000").toString();
    }

    private String futureTargetGroupArn(ContainerRequestContext ctx, String region, String accountId) {
        String name = formRequestResolver.firstParameter(ctx, "Name");
        return name == null || name.isBlank()
                ? "*"
                : AwsArnUtils.Arn.of("elasticloadbalancing", region, accountId,
                        "targetgroup/" + name + "/0000000000000000").toString();
    }

    private static String futureListenerArn(String loadBalancerArn) {
        String marker = ":loadbalancer/";
        int markerIndex = loadBalancerArn == null ? -1 : loadBalancerArn.indexOf(marker);
        if (markerIndex < 0) {
            return "*";
        }
        return loadBalancerArn.substring(0, markerIndex)
                + ":listener/" + loadBalancerArn.substring(markerIndex + marker.length())
                + "/0000000000000000";
    }

    private String exactFormResource(ContainerRequestContext ctx, String parameter) {
        String resource = formRequestResolver.firstParameter(ctx, parameter);
        return resource == null || resource.isBlank() ? "*" : resource;
    }

    // ── Auto Scaling ─────────────────────────────────────────────────────────────
    private String buildAutoScalingArn(ContainerRequestContext ctx, String region, String accountId) {
        String action = formRequestResolver.firstParameter(ctx, "Action");
        if ("CreateAutoScalingGroup".equals(action)) {
            return futureAutoScalingGroupArn(
                    formRequestResolver.firstParameter(ctx, "AutoScalingGroupName"), region, accountId);
        }
        if ("CreateOrUpdateTags".equals(action)) {
            return exactAutoScalingGroupArn(
                    formRequestResolver.firstParameter(ctx, "Tags.member.1.ResourceId"), region, accountId);
        }
        if ("UpdateAutoScalingGroup".equals(action)
                || "StartInstanceRefresh".equals(action)
                || "SuspendProcesses".equals(action)
                || "ResumeProcesses".equals(action)
                || "DeleteAutoScalingGroup".equals(action)
                || "PutLifecycleHook".equals(action)
                || "DeleteLifecycleHook".equals(action)
                || "PutScalingPolicy".equals(action)
                || "DeletePolicy".equals(action)) {
            String name = formRequestResolver.firstParameter(ctx, "AutoScalingGroupName");
            return exactAutoScalingGroupArn(name, region, accountId);
        }
        return "*";
    }

    private String exactAutoScalingGroupArn(String name, String region, String accountId) {
        if (name == null || name.isBlank()) {
            return "*";
        }
        try {
            return autoScalingService.requireAutoScalingGroup(region, name).getAutoScalingGroupArn();
        } catch (AwsException e) {
            LOG.debugv("Unable to resolve Auto Scaling group {0}: {1}", name, e.getMessage());
            return futureAutoScalingGroupArn(name, region, accountId);
        }
    }

    private String futureAutoScalingGroupArn(String name, String region, String accountId) {
        return name == null || name.isBlank()
                ? "*"
                : AwsArnUtils.Arn.of("autoscaling", region, accountId,
                        "autoScalingGroup:00000000-0000-0000-0000-000000000000:"
                                + "autoScalingGroupName/" + name).toString();
    }

    private String extractSegmentAfter(String path, String segment) {
        String marker = "/" + segment + "/";
        int idx = path.indexOf(marker);
        if (idx < 0) return null;
        String after = path.substring(idx + marker.length());
        // take only the first segment (stop at next /)
        int slash = after.indexOf('/');
        return slash > 0 ? after.substring(0, slash) : after;
    }

    private String firstFormParam(ContainerRequestContext ctx, String name) {
        // Form params are typically available as query params in REST-Assured / JAX-RS
        String v = ctx.getUriInfo().getQueryParameters().getFirst(name);
        return v;
    }

    private JsonNode readJsonRequest(ContainerRequestContext ctx) {
        InputStream input = ctx.getEntityStream();
        if (input == null) {
            return null;
        }

        byte[] body;
        try {
            body = input.readAllBytes();
        } catch (IOException e) {
            LOG.debugv(e, "Unable to read JSON request body while resolving IAM resource");
            return null;
        }
        ctx.setEntityStream(new ByteArrayInputStream(body));
        if (body.length == 0) {
            return null;
        }

        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            LOG.debugv(e, "Unable to parse JSON request body while resolving IAM resource");
            return null;
        }
    }

    private String textField(JsonNode request, String name) {
        if (request == null) {
            return null;
        }
        JsonNode value = request.path(name);
        return value.isTextual() ? value.asText() : null;
    }
}
