package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsFormRequestResolver;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import org.jboss.logging.Logger;

import java.util.LinkedHashMap;
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
    private final Ec2Service ec2Service;

    @Inject
    public ResourceArnBuilder(IamService iamService, AwsFormRequestResolver formRequestResolver,
                              Ec2Service ec2Service) {
        this.iamService = iamService;
        this.formRequestResolver = formRequestResolver;
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
            case "ec2"            -> buildEc2Arn(ctx, region, accountId);
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
        if ("ec2:CreateLaunchTemplate".equals(action) && hasRequestTags(conditionContext)) {
            Map<String, List<String>> createTagsContext = new LinkedHashMap<>(conditionContext);
            createTagsContext.put("ec2:CreateAction", List.of("CreateLaunchTemplate"));
            return List.of(new AuthorizationRequest(
                    "ec2:CreateTags", primaryResource, Map.copyOf(createTagsContext)));
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

    private String buildEc2Arn(ContainerRequestContext ctx, String region, String accountId) {
        String action = formRequestResolver.firstParameter(ctx, "Action");
        if ("CreateLaunchTemplate".equals(action)) {
            return AwsArnUtils.Arn.of("ec2", region, accountId,
                    "launch-template/lt-00000000000000000").toString();
        }
        if (!"DeleteLaunchTemplate".equals(action)) {
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
