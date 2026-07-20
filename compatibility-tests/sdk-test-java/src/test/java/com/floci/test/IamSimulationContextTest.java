package com.floci.test;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.ContextEntry;
import software.amazon.awssdk.services.iam.model.ContextKeyTypeEnum;
import software.amazon.awssdk.services.iam.model.CreateRoleRequest;
import software.amazon.awssdk.services.iam.model.DeleteRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.DeleteRoleRequest;
import software.amazon.awssdk.services.iam.model.PolicyEvaluationDecisionType;
import software.amazon.awssdk.services.iam.model.PutRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.SimulatePrincipalPolicyRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IamSimulationContextTest {

    private static final String TRUST_POLICY = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
            """;
    private static final String CONTEXT_POLICY = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"example:UpdateResource","Resource":"arn:aws:example:us-east-1:000000000000:resource/*","Condition":{"ForAnyValue:StringEquals":{"aws:ResourceTag/managed-by":["floci","trusted"]},"ForAllValues:StringEquals":{"aws:TagKeys":["managed-by","definition-id"]},"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}
            """;

    @Test
    void simulatesMultiValueAndMultiContextEntries() {
        String roleName = TestFixtures.uniqueName("sdk-simulation-context");
        String roleArn = "arn:aws:iam::000000000000:role/" + roleName;
        String policyName = "context-policy";
        String resourceArn = "arn:aws:example:us-east-1:000000000000:resource/example";

        try (IamClient iam = TestFixtures.iamClient()) {
            iam.createRole(CreateRoleRequest.builder()
                    .roleName(roleName)
                    .assumeRolePolicyDocument(TRUST_POLICY)
                    .build());
            try {
                iam.putRolePolicy(PutRolePolicyRequest.builder()
                        .roleName(roleName)
                        .policyName(policyName)
                        .policyDocument(CONTEXT_POLICY)
                        .build());

                assertDecision(iam, simulationRequest(roleArn, resourceArn,
                                List.of("not-floci", "floci"),
                                List.of("managed-by", "definition-id"), true),
                        PolicyEvaluationDecisionType.ALLOWED);
                assertDecision(iam, simulationRequest(roleArn, resourceArn,
                                List.of("not-floci", "unknown"),
                                List.of("managed-by", "definition-id"), true),
                        PolicyEvaluationDecisionType.IMPLICIT_DENY);
                assertDecision(iam, simulationRequest(roleArn, resourceArn,
                                List.of("floci"),
                                List.of("managed-by", "forbidden"), true),
                        PolicyEvaluationDecisionType.IMPLICIT_DENY);
                assertDecision(iam, simulationRequest(roleArn, resourceArn,
                                List.of("floci"),
                                List.of("managed-by", "definition-id"), false),
                        PolicyEvaluationDecisionType.IMPLICIT_DENY);
            } finally {
                iam.deleteRolePolicy(DeleteRolePolicyRequest.builder()
                        .roleName(roleName)
                        .policyName(policyName)
                        .build());
                iam.deleteRole(DeleteRoleRequest.builder().roleName(roleName).build());
            }
        }
    }

    private void assertDecision(
            IamClient iam, SimulatePrincipalPolicyRequest request,
            PolicyEvaluationDecisionType expectedDecision) {
        assertThat(iam.simulatePrincipalPolicy(request).evaluationResults())
                .singleElement()
                .extracting(result -> result.evalDecision())
                .isEqualTo(expectedDecision);
    }

    private SimulatePrincipalPolicyRequest simulationRequest(
            String roleArn, String resourceArn, List<String> managedByValues,
            List<String> tagKeys, boolean includeRegion) {
        var builder = SimulatePrincipalPolicyRequest.builder()
                .policySourceArn(roleArn)
                .actionNames("example:UpdateResource")
                .resourceArns(resourceArn)
                .contextEntries(
                        context("aws:ResourceTag/managed-by", managedByValues),
                        context("aws:TagKeys", tagKeys));
        if (includeRegion) {
            builder.contextEntries(
                    context("aws:ResourceTag/managed-by", managedByValues),
                    context("aws:TagKeys", tagKeys),
                    context("aws:RequestedRegion", List.of("us-east-1")));
        }
        return builder.build();
    }

    private ContextEntry context(String name, List<String> values) {
        return ContextEntry.builder()
                .contextKeyName(name)
                .contextKeyValues(values)
                .contextKeyType(ContextKeyTypeEnum.STRING)
                .build();
    }
}
