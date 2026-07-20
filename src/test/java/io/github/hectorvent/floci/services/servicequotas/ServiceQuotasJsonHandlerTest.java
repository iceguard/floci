package io.github.hectorvent.floci.services.servicequotas;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServiceQuotasJsonHandlerTest {

    private static final String REGION = "us-east-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ServiceQuotasJsonHandler handler;

    @BeforeEach
    void setUp() {
        handler = new ServiceQuotasJsonHandler(MAPPER,
                new RegionResolver(REGION, "123456789012"), serviceQuotasConfig(17));
    }

    @Test
    void getOperationsReturnAwsQuotaShapeForOwningService() {
        ObjectNode request = quotaRequest(ServiceQuotaCatalog.VPC_SERVICE_CODE,
                ServiceQuotaCatalog.NAT_GATEWAYS_PER_AVAILABILITY_ZONE);

        JsonNode quota = entity(handler.handle("GetServiceQuota", request, REGION)).get("Quota");
        JsonNode defaultQuota = entity(handler.handle(
                "GetAWSDefaultServiceQuota", request, REGION)).get("Quota");

        assertEquals(defaultQuota, quota);
        assertEquals(ServiceQuotaCatalog.VPC_SERVICE_CODE, quota.get("ServiceCode").asText());
        assertEquals(ServiceQuotaCatalog.VPC_SERVICE_NAME, quota.get("ServiceName").asText());
        assertEquals(ServiceQuotaCatalog.NAT_GATEWAYS_PER_AVAILABILITY_ZONE,
                quota.get("QuotaCode").asText());
        assertEquals("NAT gateways per Availability Zone", quota.get("QuotaName").asText());
        assertEquals(5.0, quota.get("Value").asDouble());
        assertEquals("None", quota.get("Unit").asText());
        assertTrue(quota.get("Adjustable").asBoolean());
        assertFalse(quota.get("GlobalQuota").asBoolean());
        assertEquals("ACCOUNT", quota.get("QuotaAppliedAtLevel").asText());
        assertEquals("arn:aws:servicequotas:us-east-1:123456789012:vpc/"
                        + ServiceQuotaCatalog.NAT_GATEWAYS_PER_AVAILABILITY_ZONE,
                quota.get("QuotaArn").asText());
        assertFalse(quota.has("Arn"));
    }

    @Test
    void catalogKeepsEc2AndVpcQuotaOwnershipSeparate() {
        JsonNode ec2 = entity(handler.handle("ListServiceQuotas",
                MAPPER.createObjectNode().put("ServiceCode", ServiceQuotaCatalog.EC2_SERVICE_CODE),
                REGION));
        JsonNode vpc = entity(handler.handle("ListServiceQuotas",
                MAPPER.createObjectNode().put("ServiceCode", ServiceQuotaCatalog.VPC_SERVICE_CODE),
                REGION));

        assertEquals(2, ec2.get("Quotas").size());
        assertEquals(ServiceQuotaCatalog.EIP_PER_REGION,
                ec2.get("Quotas").get(0).get("QuotaCode").asText());
        assertEquals(ServiceQuotaCatalog.STANDARD_ON_DEMAND_VCPUS,
                ec2.get("Quotas").get(1).get("QuotaCode").asText());
        assertEquals(1, vpc.get("Quotas").size());
        assertEquals(ServiceQuotaCatalog.NAT_GATEWAYS_PER_AVAILABILITY_ZONE,
                vpc.get("Quotas").get(0).get("QuotaCode").asText());

        AwsException wrongOwner = assertThrows(AwsException.class,
                () -> handler.handle("GetServiceQuota",
                        quotaRequest(ServiceQuotaCatalog.EC2_SERVICE_CODE,
                                ServiceQuotaCatalog.NAT_GATEWAYS_PER_AVAILABILITY_ZONE),
                        REGION));
        assertEquals("NoSuchResourceException", wrongOwner.getErrorCode());
    }

    @Test
    void ec2VcpuDefaultAndAppliedOperationsUseDistinctValuesAndRegionalArns() {
        ObjectNode request = quotaRequest(ServiceQuotaCatalog.EC2_SERVICE_CODE,
                ServiceQuotaCatalog.STANDARD_ON_DEMAND_VCPUS);

        JsonNode appliedEast = entity(handler.handle("GetServiceQuota", request, REGION)).get("Quota");
        JsonNode defaultWest = entity(handler.handle(
                "GetAWSDefaultServiceQuota", request, "us-west-2")).get("Quota");
        JsonNode appliedList = entity(handler.handle("ListServiceQuotas",
                MAPPER.createObjectNode().put("ServiceCode", ServiceQuotaCatalog.EC2_SERVICE_CODE),
                REGION));
        JsonNode defaultList = entity(handler.handle("ListAWSDefaultServiceQuotas",
                MAPPER.createObjectNode().put("ServiceCode", ServiceQuotaCatalog.EC2_SERVICE_CODE),
                "us-west-2"));

        assertEquals(17.0, appliedEast.get("Value").asDouble());
        assertEquals(5.0, defaultWest.get("Value").asDouble());
        assertEquals("arn:aws:servicequotas:us-east-1:123456789012:ec2/L-1216C47A",
                appliedEast.get("QuotaArn").asText());
        assertEquals("arn:aws:servicequotas:us-west-2:123456789012:ec2/L-1216C47A",
                defaultWest.get("QuotaArn").asText());
        assertEquals(17.0, quotaByCode(appliedList, ServiceQuotaCatalog.STANDARD_ON_DEMAND_VCPUS)
                .get("Value").asDouble());
        assertEquals(5.0, quotaByCode(defaultList, ServiceQuotaCatalog.STANDARD_ON_DEMAND_VCPUS)
                .get("Value").asDouble());
        assertEquals("None", appliedEast.get("Unit").asText());
        assertTrue(appliedEast.get("Adjustable").asBoolean());
        assertFalse(appliedEast.get("GlobalQuota").asBoolean());
        assertEquals("ACCOUNT", appliedEast.get("QuotaAppliedAtLevel").asText());
    }

    @Test
    void catalogExposesConfiguredAppliedVcpuValueForEc2Consumers() {
        assertEquals(23.0, ServiceQuotaCatalog.appliedValue(serviceQuotasConfig(23),
                ServiceQuotaCatalog.EC2_SERVICE_CODE,
                ServiceQuotaCatalog.STANDARD_ON_DEMAND_VCPUS).orElseThrow());
        assertEquals(5.0, ServiceQuotaCatalog.find(ServiceQuotaCatalog.EC2_SERVICE_CODE,
                ServiceQuotaCatalog.STANDARD_ON_DEMAND_VCPUS).orElseThrow().awsDefaultValue());
        assertTrue(ServiceQuotaCatalog.appliedValue(serviceQuotasConfig(23),
                ServiceQuotaCatalog.EC2_SERVICE_CODE, "L-unknown").isEmpty());
    }

    @Test
    void listServiceQuotasFiltersModeledAccountLevelQuotas() {
        ObjectNode base = MAPPER.createObjectNode()
                .put("ServiceCode", ServiceQuotaCatalog.VPC_SERVICE_CODE);
        ObjectNode byCode = base.deepCopy()
                .put("QuotaCode", ServiceQuotaCatalog.NAT_GATEWAYS_PER_AVAILABILITY_ZONE);
        ObjectNode wrongCode = base.deepCopy()
                .put("QuotaCode", ServiceQuotaCatalog.EIP_PER_REGION);
        ObjectNode all = base.deepCopy().put("QuotaAppliedAtLevel", "ALL");
        ObjectNode resource = base.deepCopy().put("QuotaAppliedAtLevel", "RESOURCE");

        JsonNode defaultLevel = entity(handler.handle("ListServiceQuotas", base, REGION));
        JsonNode codeMatch = entity(handler.handle("ListServiceQuotas", byCode, REGION));
        JsonNode codeMiss = entity(handler.handle("ListServiceQuotas", wrongCode, REGION));
        JsonNode allLevels = entity(handler.handle("ListServiceQuotas", all, REGION));
        JsonNode resourceLevel = entity(handler.handle("ListServiceQuotas", resource, REGION));

        assertEquals(1, defaultLevel.get("Quotas").size());
        assertEquals("ACCOUNT",
                defaultLevel.get("Quotas").get(0).get("QuotaAppliedAtLevel").asText());
        assertEquals(1, codeMatch.get("Quotas").size());
        assertEquals(0, codeMiss.get("Quotas").size());
        assertEquals(1, allLevels.get("Quotas").size());
        assertEquals(0, resourceLevel.get("Quotas").size());
    }

    @Test
    void listServicesReturnsBothOwnersWithDeterministicPagination() {
        ObjectNode firstRequest = MAPPER.createObjectNode().put("MaxResults", 1);
        JsonNode first = entity(handler.handle("ListServices", firstRequest, REGION));
        ObjectNode secondRequest = firstRequest.deepCopy()
                .put("NextToken", first.get("NextToken").asText());
        JsonNode second = entity(handler.handle("ListServices", secondRequest, REGION));

        assertEquals(1, first.get("Services").size());
        assertEquals(ServiceQuotaCatalog.EC2_SERVICE_CODE,
                first.get("Services").get(0).get("ServiceCode").asText());
        assertEquals(ServiceQuotaCatalog.EC2_SERVICE_NAME,
                first.get("Services").get(0).get("ServiceName").asText());
        assertTrue(first.hasNonNull("NextToken"));
        assertEquals(1, second.get("Services").size());
        assertEquals(ServiceQuotaCatalog.VPC_SERVICE_CODE,
                second.get("Services").get(0).get("ServiceCode").asText());
        assertEquals(ServiceQuotaCatalog.VPC_SERVICE_NAME,
                second.get("Services").get(0).get("ServiceName").asText());
        assertFalse(second.has("NextToken"));
    }

    @Test
    void unknownQuotaUsesAwsErrorShape() {
        AwsException error = assertThrows(AwsException.class,
                () -> handler.handle("GetServiceQuota",
                        quotaRequest(ServiceQuotaCatalog.EC2_SERVICE_CODE, "L-unknown"), REGION));

        assertEquals("NoSuchResourceException", error.getErrorCode());
        assertEquals("The specified resource does not exist.", error.getMessage());
        assertEquals(400, error.getHttpStatus());
    }

    @Test
    void missingRequiredFieldUsesTypedIllegalArgument() {
        AwsException error = assertThrows(AwsException.class,
                () -> handler.handle("ListServiceQuotas", MAPPER.createObjectNode(), REGION));

        assertIllegalArgument(error,
                "1 validation error detected: Value null at 'serviceCode' failed to satisfy constraint: "
                        + "Member must not be null");
    }

    @Test
    void wrongFieldTypeUsesTypedIllegalArgument() {
        ObjectNode request = MAPPER.createObjectNode().put("ServiceCode", 7);

        AwsException error = assertThrows(AwsException.class,
                () -> handler.handle("ListServiceQuotas", request, REGION));

        assertIllegalArgument(error,
                "1 validation error detected: Value at 'serviceCode' failed to satisfy constraint: "
                        + "Member must be a string");
    }

    @Test
    void patternAndLengthViolationsUseTypedIllegalArgument() {
        ObjectNode invalidService = MAPPER.createObjectNode().put("ServiceCode", "_");
        String oversizedQuotaCode = "A" + "1".repeat(128);

        AwsException patternError = assertThrows(AwsException.class,
                () -> handler.handle("ListServiceQuotas", invalidService, REGION));
        AwsException lengthError = assertThrows(AwsException.class,
                () -> handler.handle("GetServiceQuota",
                        quotaRequest(ServiceQuotaCatalog.EC2_SERVICE_CODE, oversizedQuotaCode), REGION));

        assertIllegalArgument(patternError,
                "1 validation error detected: Value '_' at 'serviceCode' failed to satisfy constraint: "
                        + "Member must satisfy regular expression pattern: "
                        + "[a-zA-Z][a-zA-Z0-9-]{1,63}");
        assertIllegalArgument(lengthError,
                "1 validation error detected: Value '" + oversizedQuotaCode
                        + "' at 'quotaCode' failed to satisfy constraint: "
                        + "Member must have length less than or equal to 128");
    }

    @Test
    void invalidMaxResultsUsesTypedIllegalArgument() {
        ObjectNode wrongType = MAPPER.createObjectNode().put("MaxResults", "1");
        ObjectNode belowMinimum = MAPPER.createObjectNode().put("MaxResults", 0);
        ObjectNode aboveMaximum = MAPPER.createObjectNode().put("MaxResults", 101);

        AwsException typeError = assertThrows(AwsException.class,
                () -> handler.handle("ListServices", wrongType, REGION));
        AwsException minimumError = assertThrows(AwsException.class,
                () -> handler.handle("ListServices", belowMinimum, REGION));
        AwsException maximumError = assertThrows(AwsException.class,
                () -> handler.handle("ListServices", aboveMaximum, REGION));

        assertIllegalArgument(typeError,
                "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
                        + "Member must be an integer");
        assertIllegalArgument(minimumError,
                "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
                        + "Member must have value greater than or equal to 1");
        assertIllegalArgument(maximumError,
                "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
                        + "Member must have value less than or equal to 100");
    }

    @Test
    void invalidAppliedLevelUsesTypedIllegalArgument() {
        ObjectNode request = MAPPER.createObjectNode()
                .put("ServiceCode", ServiceQuotaCatalog.EC2_SERVICE_CODE)
                .put("QuotaAppliedAtLevel", "ORGANIZATION");

        AwsException error = assertThrows(AwsException.class,
                () -> handler.handle("ListServiceQuotas", request, REGION));

        assertIllegalArgument(error,
                "1 validation error detected: Value 'ORGANIZATION' at 'quotaAppliedAtLevel' "
                        + "failed to satisfy constraint: Member must satisfy enum value set: "
                        + "[ACCOUNT, RESOURCE, ALL]");
    }

    @Test
    void accountLevelQuotaRejectsResourceContextWithTypedAwsError() {
        ObjectNode request = quotaRequest(ServiceQuotaCatalog.EC2_SERVICE_CODE,
                ServiceQuotaCatalog.STANDARD_ON_DEMAND_VCPUS)
                .put("ContextId", "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0");

        AwsException error = assertThrows(AwsException.class,
                () -> handler.handle("GetServiceQuota", request, REGION));

        assertEquals("NoSuchResourceException", error.getErrorCode());
        assertEquals("The specified resource does not exist.", error.getMessage());
        assertEquals(400, error.getHttpStatus());
    }

    @Test
    void contextIdWrongTypeUsesTypedIllegalArgumentBeforeSemanticValidation() {
        ObjectNode request = quotaRequest(ServiceQuotaCatalog.EC2_SERVICE_CODE,
                ServiceQuotaCatalog.STANDARD_ON_DEMAND_VCPUS)
                .put("ContextId", 7);

        AwsException error = assertThrows(AwsException.class,
                () -> handler.handle("GetServiceQuota", request, REGION));

        assertIllegalArgument(error,
                "1 validation error detected: Value at 'contextId' failed to satisfy constraint: "
                        + "Member must be a string");
    }

    @Test
    void semanticPaginationMismatchUsesTypedPaginationError() {
        ObjectNode request = MAPPER.createObjectNode().put("NextToken", "YWJj");

        AwsException error = assertThrows(AwsException.class,
                () -> handler.handle("ListServices", request, REGION));

        assertEquals("InvalidPaginationTokenException", error.getErrorCode());
        assertEquals("The pagination token is invalid.", error.getMessage());
        assertEquals(400, error.getHttpStatus());
    }

    @Test
    void forgedTerminalPaginationOffsetsAreRejected() {
        ObjectNode zero = MAPPER.createObjectNode().put("NextToken",
                token("ListServices", "services", 0));
        ObjectNode exactlyAtEnd = MAPPER.createObjectNode().put("NextToken",
                token("ListServices", "services", ServiceQuotaCatalog.services().size()));

        AwsException zeroError = assertThrows(AwsException.class,
                () -> handler.handle("ListServices", zero, REGION));
        AwsException terminalError = assertThrows(AwsException.class,
                () -> handler.handle("ListServices", exactlyAtEnd, REGION));

        assertEquals("InvalidPaginationTokenException", zeroError.getErrorCode());
        assertEquals("InvalidPaginationTokenException", terminalError.getErrorCode());
    }

    @Test
    void paginationTokenPatternViolationUsesTypedIllegalArgument() {
        ObjectNode request = MAPPER.createObjectNode().put("NextToken", "not-a-token");

        AwsException error = assertThrows(AwsException.class,
                () -> handler.handle("ListServices", request, REGION));

        assertIllegalArgument(error,
                "1 validation error detected: Value 'not-a-token' at 'nextToken' "
                        + "failed to satisfy constraint: Member must satisfy regular expression pattern: "
                        + "^[a-zA-Z0-9/+]*={0,2}$");
    }

    private static ObjectNode quotaRequest(String serviceCode, String quotaCode) {
        return MAPPER.createObjectNode()
                .put("ServiceCode", serviceCode)
                .put("QuotaCode", quotaCode);
    }

    private static JsonNode quotaByCode(JsonNode response, String quotaCode) {
        for (JsonNode quota : response.get("Quotas")) {
            if (quotaCode.equals(quota.get("QuotaCode").asText())) {
                return quota;
            }
        }
        throw new AssertionError("Missing quota " + quotaCode);
    }

    private static String token(String action, String scope, int offset) {
        return Base64.getEncoder().withoutPadding().encodeToString(
                (action + ":" + scope + ":" + offset).getBytes(StandardCharsets.UTF_8));
    }

    private static EmulatorConfig.ServiceQuotasServiceConfig serviceQuotasConfig(int appliedVcpus) {
        return new EmulatorConfig.ServiceQuotasServiceConfig() {
            @Override
            public boolean enabled() {
                return true;
            }

            @Override
            public int standardOnDemandVcpus() {
                return appliedVcpus;
            }
        };
    }

    private static ObjectNode entity(Response response) {
        return (ObjectNode) response.getEntity();
    }

    private static void assertIllegalArgument(AwsException error, String message) {
        assertEquals("IllegalArgumentException", error.getErrorCode());
        assertEquals(message, error.getMessage());
        assertEquals(400, error.getHttpStatus());
    }
}
