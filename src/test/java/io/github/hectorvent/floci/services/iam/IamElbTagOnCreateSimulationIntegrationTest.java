package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.SimulationDecision;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
class IamElbTagOnCreateSimulationIntegrationTest {

    private static final String ACCOUNT_ID = "222233334444";
    private static final String REGION = "us-west-2";
    private static final String MANAGED_BY_KEY = "aws:RequestTag/example.io:managed-by";
    private static final String CREATE_ACTION_KEY = "elasticloadbalancing:CreateAction";

    @Inject
    IamPolicyEvaluator evaluator;

    @Test
    void simulatesScopedTargetGroupTagOnCreateWithoutChangingRuntimeMatching() {
        String policy = tagOnCreatePolicy(
                "aws", REGION, ACCOUNT_ID, "targetgroup/*", "CreateTargetGroup");
        Map<String, String> matchingContext = context("CreateTargetGroup", "floci");

        assertEquals(
                SimulationDecision.ALLOWED,
                simulate(policy, matchingContext));
        assertEquals(
                Decision.DENY,
                evaluator.evaluate(
                        CallerContext.of(List.of(policy)),
                        null,
                        "elasticloadbalancing:AddTags",
                        "*",
                        matchingContext));
    }

    @Test
    void requiresMatchingCreateActionAndRequestContext() {
        String policy = tagOnCreatePolicy(
                "aws", REGION, ACCOUNT_ID, "targetgroup/*", "CreateTargetGroup");

        assertEquals(SimulationDecision.IMPLICIT_DENY, simulate(policy, context("CreateLoadBalancer", "floci")));
        assertEquals(SimulationDecision.IMPLICIT_DENY, simulate(policy, context("CreateTargetGroup", "other")));
        assertEquals(
                SimulationDecision.IMPLICIT_DENY,
                simulate(policy, Map.of(MANAGED_BY_KEY, "floci")));
        assertEquals(
                SimulationDecision.IMPLICIT_DENY,
                evaluator.simulatePrincipalPolicy(
                        CallerContext.of(List.of(policy)),
                        "elasticloadbalancing:DeleteTargetGroup",
                        "*",
                        context("CreateTargetGroup", "floci")));
    }

    @Test
    void rejectsWrongOrMalformedFutureResourcePatterns() {
        assertImplicitDeny(tagOnCreatePolicy(
                "aws", REGION, ACCOUNT_ID, "listener/app/*", "CreateTargetGroup"));
        assertImplicitDeny(tagOnCreatePolicy(
                "aws-cn", REGION, ACCOUNT_ID, "targetgroup/*", "CreateTargetGroup"));
        assertImplicitDeny(tagOnCreatePolicy(
                "aws", "*", ACCOUNT_ID, "targetgroup/*", "CreateTargetGroup"));
        assertImplicitDeny(tagOnCreatePolicy(
                "aws", REGION, "*", "targetgroup/*", "CreateTargetGroup"));
        assertImplicitDeny("""
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "elasticloadbalancing:AddTags",
                    "Resource": "not-an-arn/targetgroup/*",
                    "Condition": {
                      "StringEquals": {
                        "aws:RequestTag/example.io:managed-by": "floci",
                        "elasticloadbalancing:CreateAction": "CreateTargetGroup"
                      }
                    }
                  }]
                }
                """);
    }

    private void assertImplicitDeny(String policy) {
        assertEquals(
                SimulationDecision.IMPLICIT_DENY,
                simulate(policy, context("CreateTargetGroup", "floci")));
    }

    private SimulationDecision simulate(String policy, Map<String, String> context) {
        return evaluator.simulatePrincipalPolicy(
                CallerContext.of(List.of(policy)),
                "elasticloadbalancing:AddTags",
                "*",
                context);
    }

    private static Map<String, String> context(String createAction, String managedBy) {
        return Map.of(CREATE_ACTION_KEY, createAction, MANAGED_BY_KEY, managedBy);
    }

    private static String tagOnCreatePolicy(
            String partition,
            String region,
            String accountId,
            String resourceSuffix,
            String createAction) {
        return """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Allow",
                    "Action": "elasticloadbalancing:AddTags",
                    "Resource": "arn:%s:elasticloadbalancing:%s:%s:%s",
                    "Condition": {
                      "StringEquals": {
                        "aws:RequestTag/example.io:managed-by": "floci",
                        "elasticloadbalancing:CreateAction": "%s"
                      }
                    }
                  }]
                }
                """.formatted(partition, region, accountId, resourceSuffix, createAction);
    }
}
