package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsFormRequestResolver;
import io.github.hectorvent.floci.core.common.AwsJsonRequestResolver;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import io.github.hectorvent.floci.services.ec2.model.Tag;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import org.jboss.logging.Logger;

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
    private final AwsJsonRequestResolver jsonRequestResolver;
    private final Ec2Service ec2Service;

    @Inject
    public ResourceArnBuilder(IamService iamService, AwsFormRequestResolver formRequestResolver,
                              AwsJsonRequestResolver jsonRequestResolver, Ec2Service ec2Service) {
        this.iamService = iamService;
        this.formRequestResolver = formRequestResolver;
        this.jsonRequestResolver = jsonRequestResolver;
        this.ec2Service = ec2Service;
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
            case "kms"            -> buildKmsArn(path, region, accountId);
            case "iam"            -> buildIamArn(ctx, accountId);
            default               -> "*";
        };
    }

    public List<AuthorizationRequest> resourceAuthorizations(
            String credentialScope, String action, ContainerRequestContext ctx,
            String region, String accountId) {
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
        return List.of();
    }

    public List<AuthorizationRequest> additionalAuthorizations(
            String action, String primaryResource, Map<String, List<String>> conditionContext) {
        return List.of();
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
        return AwsArnUtils.Arn.of("secretsmanager", region, accountId, "secret:*").toString();
    }

    // ── SSM ──────────────────────────────────────────────────────────────────────
    private String buildSsmArn(ContainerRequestContext ctx, String region, String accountId) {
        return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/*").toString();
    }

    // ── KMS ──────────────────────────────────────────────────────────────────────
    private String buildKmsArn(String path, String region, String accountId) {
        String keyId = extractSegmentAfter(path, "keys");
        if (keyId == null) return AwsArnUtils.Arn.of("kms", region, accountId, "key/*").toString();
        return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyId).toString();
    }

    // ── IAM ─────────────────────────────────────────────────────────────────────
    private String buildIamArn(ContainerRequestContext ctx, String accountId) {
        String action = formRequestResolver.firstParameter(ctx, "Action");
        return switch (action == null ? "" : action) {
            case "CreateRole" -> requestedRoleArn(ctx, accountId);
            case "AttachRolePolicy", "DetachRolePolicy" -> existingRoleArn(ctx, accountId);
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

    // ── Helpers ──────────────────────────────────────────────────────────────────

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
}
