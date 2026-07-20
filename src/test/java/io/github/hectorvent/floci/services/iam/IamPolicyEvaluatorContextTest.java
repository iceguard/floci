package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.SimulationDecision.ALLOWED;
import static io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.SimulationDecision.IMPLICIT_DENY;
import static org.junit.jupiter.api.Assertions.assertEquals;

class IamPolicyEvaluatorContextTest {

    private static final String ACTION = "example:UpdateResource";
    private static final String RESOURCE = "arn:aws:example:us-east-1:000000000000:resource/example";

    private final IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());

    @Test
    void evaluatesScalarAndMultiValueContexts() {
        CallerContext caller = callerWithCondition(
                "StringEquals", "aws:ResourceTag/managed-by", List.of("floci"));

        assertEquals(ALLOWED, simulate(caller, Map.of("aws:ResourceTag/managed-by", "floci")));
        assertEquals(ALLOWED, simulate(caller,
                Map.of("aws:ResourceTag/managed-by", List.of("other", "floci"))));
        assertEquals(IMPLICIT_DENY, simulate(caller,
                Map.of("aws:ResourceTag/managed-by", List.of("other", "unknown"))));
        assertEquals(IMPLICIT_DENY, simulate(caller, Map.of()));
    }

    @Test
    void evaluatesForAnyValueQualifier() {
        CallerContext caller = callerWithCondition(
                "ForAnyValue:StringLike", "aws:TagKeys", List.of("team-*", "owner"));

        assertEquals(ALLOWED,
                simulate(caller, Map.of("aws:TagKeys", List.of("environment", "team-platform"))));
        assertEquals(IMPLICIT_DENY,
                simulate(caller, Map.of("aws:TagKeys", List.of("environment", "cost-center"))));
        assertEquals(IMPLICIT_DENY, simulate(caller, Map.of()));
    }

    @Test
    void evaluatesForAllValuesQualifierIncludingAbsentContext() {
        CallerContext caller = callerWithCondition(
                "ForAllValues:StringEquals", "aws:TagKeys", List.of("environment", "owner"));

        assertEquals(ALLOWED,
                simulate(caller, Map.of("aws:TagKeys", List.of("environment", "owner"))));
        assertEquals(IMPLICIT_DENY,
                simulate(caller, Map.of("aws:TagKeys", List.of("environment", "cost-center"))));
        assertEquals(ALLOWED, simulate(caller, Map.of()));
    }

    @Test
    void evaluatesNegatedOperatorsAgainstEveryPolicyValue() {
        CallerContext caller = callerWithCondition(
                "ForAllValues:StringNotEquals", "aws:TagKeys", List.of("restricted", "internal"));

        assertEquals(ALLOWED,
                simulate(caller, Map.of("aws:TagKeys", List.of("environment", "owner"))));
        assertEquals(IMPLICIT_DENY,
                simulate(caller, Map.of("aws:TagKeys", List.of("environment", "restricted"))));
    }

    private IamPolicyEvaluator.SimulationDecision simulate(CallerContext caller, Map<String, ?> context) {
        return evaluator.simulatePrincipalPolicy(caller, ACTION, RESOURCE, context);
    }

    private CallerContext callerWithCondition(String operator, String key, List<String> values) {
        String conditionValues = new ObjectMapper().valueToTree(values).toString();
        String policy = """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow",
                  "Action":"%s",
                  "Resource":"%s",
                  "Condition":{"%s":{"%s":%s}}
                }]}
                """.formatted(ACTION, RESOURCE, operator, key, conditionValues);
        return CallerContext.of(List.of(policy));
    }
}
