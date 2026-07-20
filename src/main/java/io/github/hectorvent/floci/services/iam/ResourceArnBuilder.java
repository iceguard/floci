package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsFormRequestResolver;
import io.github.hectorvent.floci.core.common.IamConditionContextResolver.ResourceAwareConditionContext;
import io.github.hectorvent.floci.services.autoscaling.AutoScalingService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;

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
    private final AutoScalingService autoScalingService;

    @Inject
    public ResourceArnBuilder(IamService iamService, AwsFormRequestResolver formRequestResolver,
                              AutoScalingService autoScalingService) {
        this.iamService = iamService;
        this.formRequestResolver = formRequestResolver;
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
            case "kms"            -> buildKmsArn(path, region, accountId);
            case "iam"            -> buildIamArn(ctx, accountId);
            case "autoscaling"    -> buildAutoScalingArn(ctx, region, accountId);
            default               -> "*";
        };
    }

    public List<AuthorizationRequest> resourceAuthorizations(
            String credentialScope, String action, ContainerRequestContext ctx,
            String region, String accountId) {
        return List.of();
    }

    public List<String> additionalResources(String credentialScope, ContainerRequestContext ctx,
                                            String region, String accountId) {
        return List.of();
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
        if ("DeleteAutoScalingGroup".equals(action)
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
