package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.servicequotas.ServiceQuotasClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.servicequotas.model.AppliedLevelEnum;
import software.amazon.awssdk.services.servicequotas.model.GetAwsDefaultServiceQuotaRequest;
import software.amazon.awssdk.services.servicequotas.model.GetServiceQuotaRequest;
import software.amazon.awssdk.services.servicequotas.model.IllegalArgumentException;
import software.amazon.awssdk.services.servicequotas.model.InvalidPaginationTokenException;
import software.amazon.awssdk.services.servicequotas.model.ListAwsDefaultServiceQuotasRequest;
import software.amazon.awssdk.services.servicequotas.model.ListServiceQuotasRequest;
import software.amazon.awssdk.services.servicequotas.model.ListServicesRequest;
import software.amazon.awssdk.services.servicequotas.model.NoSuchResourceException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ServiceQuotasTest {

    private static final String EIP_PER_REGION = "L-0263D0A3";
    private static final String STANDARD_ON_DEMAND_VCPUS = "L-1216C47A";
    private static final String NAT_GATEWAYS_PER_AVAILABILITY_ZONE = "L-FE5A380F";
    private static final double EXPECTED_APPLIED_STANDARD_ON_DEMAND_VCPUS = Double.parseDouble(
            System.getenv().getOrDefault("FLOCI_EXPECTED_STANDARD_ON_DEMAND_VCPUS", "5"));

    private static ServiceQuotasClient serviceQuotas;

    @BeforeAll
    static void setUp() {
        serviceQuotas = TestFixtures.serviceQuotasClient();
    }

    @AfterAll
    static void tearDown() {
        if (serviceQuotas != null) {
            serviceQuotas.close();
        }
    }

    @Test
    void getQuotaOperationsDecodeCompleteAwsShape() {
        var quota = serviceQuotas.getServiceQuota(GetServiceQuotaRequest.builder()
                .serviceCode("vpc")
                .quotaCode(NAT_GATEWAYS_PER_AVAILABILITY_ZONE)
                .build()).quota();
        var defaultQuota = serviceQuotas.getAWSDefaultServiceQuota(
                GetAwsDefaultServiceQuotaRequest.builder()
                        .serviceCode("vpc")
                        .quotaCode(NAT_GATEWAYS_PER_AVAILABILITY_ZONE)
                        .build()).quota();

        assertThat(quota).isEqualTo(defaultQuota);
        assertThat(quota.serviceCode()).isEqualTo("vpc");
        assertThat(quota.serviceName()).isEqualTo("Amazon Virtual Private Cloud (Amazon VPC)");
        assertThat(quota.quotaCode()).isEqualTo(NAT_GATEWAYS_PER_AVAILABILITY_ZONE);
        assertThat(quota.quotaName()).isEqualTo("NAT gateways per Availability Zone");
        assertThat(quota.quotaArn()).isEqualTo(
                "arn:aws:servicequotas:us-east-1:000000000000:vpc/"
                        + NAT_GATEWAYS_PER_AVAILABILITY_ZONE);
        assertThat(quota.value()).isEqualTo(5.0);
        assertThat(quota.unit()).isEqualTo("None");
        assertThat(quota.adjustable()).isTrue();
        assertThat(quota.globalQuota()).isFalse();
        assertThat(quota.quotaAppliedAtLevel()).isEqualTo(AppliedLevelEnum.ACCOUNT);
    }

    @Test
    void listQuotaOperationsKeepServiceOwnershipAndApplyFilters() {
        var ec2 = serviceQuotas.listServiceQuotas(ListServiceQuotasRequest.builder()
                .serviceCode("ec2")
                .build());
        var vpcDefaults = serviceQuotas.listAWSDefaultServiceQuotas(
                ListAwsDefaultServiceQuotasRequest.builder().serviceCode("vpc").build());
        var byCode = serviceQuotas.listServiceQuotas(ListServiceQuotasRequest.builder()
                .serviceCode("vpc")
                .quotaCode(NAT_GATEWAYS_PER_AVAILABILITY_ZONE)
                .build());
        var wrongCode = serviceQuotas.listServiceQuotas(ListServiceQuotasRequest.builder()
                .serviceCode("vpc")
                .quotaCode(EIP_PER_REGION)
                .build());
        var allLevels = serviceQuotas.listServiceQuotas(ListServiceQuotasRequest.builder()
                .serviceCode("vpc")
                .quotaAppliedAtLevel(AppliedLevelEnum.ALL)
                .build());
        var resourceLevel = serviceQuotas.listServiceQuotas(ListServiceQuotasRequest.builder()
                .serviceCode("vpc")
                .quotaAppliedAtLevel(AppliedLevelEnum.RESOURCE)
                .build());

        assertThat(ec2.quotas()).extracting(quota -> quota.quotaCode())
                .containsExactly(EIP_PER_REGION, STANDARD_ON_DEMAND_VCPUS);
        assertThat(vpcDefaults.quotas()).extracting(quota -> quota.quotaCode())
                .containsExactly(NAT_GATEWAYS_PER_AVAILABILITY_ZONE);
        assertThat(byCode.quotas()).extracting(quota -> quota.quotaCode())
                .containsExactly(NAT_GATEWAYS_PER_AVAILABILITY_ZONE);
        assertThat(wrongCode.quotas()).isEmpty();
        assertThat(allLevels.quotas()).extracting(quota -> quota.quotaAppliedAtLevel())
                .containsExactly(AppliedLevelEnum.ACCOUNT);
        assertThat(resourceLevel.quotas()).isEmpty();
    }

    @Test
    void ec2VcpuDefaultAndAppliedOperationsDecodeDistinctValuesAndRegionalMetadata() {
        try (ServiceQuotasClient west = TestFixtures.serviceQuotasClient(Region.US_WEST_2)) {
            var eastApplied = serviceQuotas.getServiceQuota(GetServiceQuotaRequest.builder()
                    .serviceCode("ec2")
                    .quotaCode(STANDARD_ON_DEMAND_VCPUS)
                    .build()).quota();
            var westDefault = west.getAWSDefaultServiceQuota(GetAwsDefaultServiceQuotaRequest.builder()
                    .serviceCode("ec2")
                    .quotaCode(STANDARD_ON_DEMAND_VCPUS)
                    .build()).quota();
            var eastAppliedList = serviceQuotas.listServiceQuotas(ListServiceQuotasRequest.builder()
                    .serviceCode("ec2")
                    .build()).quotas().stream()
                    .filter(quota -> STANDARD_ON_DEMAND_VCPUS.equals(quota.quotaCode()))
                    .findFirst().orElseThrow();
            var westDefaultList = west.listAWSDefaultServiceQuotas(
                    ListAwsDefaultServiceQuotasRequest.builder().serviceCode("ec2").build())
                    .quotas().stream()
                    .filter(quota -> STANDARD_ON_DEMAND_VCPUS.equals(quota.quotaCode()))
                    .findFirst().orElseThrow();

            assertThat(eastApplied.value()).isEqualTo(EXPECTED_APPLIED_STANDARD_ON_DEMAND_VCPUS);
            assertThat(eastAppliedList.value()).isEqualTo(EXPECTED_APPLIED_STANDARD_ON_DEMAND_VCPUS);
            assertThat(westDefault.value()).isEqualTo(5.0);
            assertThat(westDefaultList.value()).isEqualTo(5.0);
            assertQuotaMetadata(eastApplied,
                    "arn:aws:servicequotas:us-east-1:000000000000:ec2/" + STANDARD_ON_DEMAND_VCPUS);
            assertQuotaMetadata(westDefault,
                    "arn:aws:servicequotas:us-west-2:000000000000:ec2/" + STANDARD_ON_DEMAND_VCPUS);
        }
    }

    @Test
    void accountLevelQuotaRejectsResourceContextAsTypedNoSuchResource() {
        assertThatThrownBy(() -> serviceQuotas.getServiceQuota(GetServiceQuotaRequest.builder()
                .serviceCode("ec2")
                .quotaCode(STANDARD_ON_DEMAND_VCPUS)
                .contextId("arn:aws:ec2:us-east-1:000000000000:instance/i-1234567890abcdef0")
                .build()))
                .isInstanceOfSatisfying(NoSuchResourceException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().errorCode()).isEqualTo("NoSuchResourceException");
                    assertThat(error.awsErrorDetails().errorMessage())
                            .isEqualTo("The specified resource does not exist.");
                    assertThat(error.requestId()).isNotBlank();
                });
    }

    @Test
    void listServicesDecodesBothCatalogEntriesWithPagination() {
        var first = serviceQuotas.listServices(ListServicesRequest.builder()
                .maxResults(1)
                .build());
        var second = serviceQuotas.listServices(ListServicesRequest.builder()
                .maxResults(1)
                .nextToken(first.nextToken())
                .build());

        assertThat(first.services()).singleElement().satisfies(service -> {
            assertThat(service.serviceCode()).isEqualTo("ec2");
            assertThat(service.serviceName())
                    .isEqualTo("Amazon Elastic Compute Cloud (Amazon EC2)");
        });
        assertThat(first.nextToken()).isNotBlank();
        assertThat(second.services()).singleElement().satisfies(service -> {
            assertThat(service.serviceCode()).isEqualTo("vpc");
            assertThat(service.serviceName())
                    .isEqualTo("Amazon Virtual Private Cloud (Amazon VPC)");
        });
        assertThat(second.nextToken()).isNull();
    }

    @Test
    void errorsDecodeToTypedSdkExceptionsWithMessagesAndRequestIds() {
        assertThatThrownBy(() -> serviceQuotas.getServiceQuota(GetServiceQuotaRequest.builder()
                .serviceCode("ec2")
                .quotaCode("L-unknown")
                .build()))
                .isInstanceOfSatisfying(NoSuchResourceException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().errorCode()).isEqualTo("NoSuchResourceException");
                    assertThat(error.awsErrorDetails().errorMessage())
                            .isEqualTo("The specified resource does not exist.");
                    assertThat(error.requestId()).isNotBlank();
                });

        assertThatThrownBy(() -> serviceQuotas.listServices(ListServicesRequest.builder()
                .nextToken("YWJj")
                .build()))
                .isInstanceOfSatisfying(InvalidPaginationTokenException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidPaginationTokenException");
                    assertThat(error.awsErrorDetails().errorMessage())
                            .isEqualTo("The pagination token is invalid.");
                    assertThat(error.requestId()).isNotBlank();
                });

        assertThatThrownBy(() -> serviceQuotas.listServices(ListServicesRequest.builder()
                .nextToken("TGlzdFNlcnZpY2VzOnNlcnZpY2VzOjI")
                .build()))
                .isInstanceOfSatisfying(InvalidPaginationTokenException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().errorCode())
                            .isEqualTo("InvalidPaginationTokenException");
                    assertThat(error.requestId()).isNotBlank();
                });
    }

    @Test
    void modeledValidationDecodesToTypedIllegalArgument() {
        assertThatThrownBy(() -> serviceQuotas.listServiceQuotas(
                ListServiceQuotasRequest.builder().build()))
                .isInstanceOfSatisfying(IllegalArgumentException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().errorCode()).isEqualTo("IllegalArgumentException");
                    assertThat(error.awsErrorDetails().errorMessage()).isEqualTo(
                            "1 validation error detected: Value null at 'serviceCode' failed to satisfy "
                                    + "constraint: Member must not be null");
                    assertThat(error.requestId()).isNotBlank();
                });

        assertThatThrownBy(() -> serviceQuotas.listServices(ListServicesRequest.builder()
                .maxResults(0)
                .build()))
                .isInstanceOfSatisfying(IllegalArgumentException.class, error -> {
                    assertThat(error.statusCode()).isEqualTo(400);
                    assertThat(error.awsErrorDetails().errorCode()).isEqualTo("IllegalArgumentException");
                    assertThat(error.awsErrorDetails().errorMessage()).isEqualTo(
                            "1 validation error detected: Value '0' at 'maxResults' failed to satisfy "
                                    + "constraint: Member must have value greater than or equal to 1");
                    assertThat(error.requestId()).isNotBlank();
                });
    }

    private static void assertQuotaMetadata(
            software.amazon.awssdk.services.servicequotas.model.ServiceQuota quota,
            String expectedArn) {
        assertThat(quota.serviceCode()).isEqualTo("ec2");
        assertThat(quota.serviceName()).isEqualTo("Amazon Elastic Compute Cloud (Amazon EC2)");
        assertThat(quota.quotaCode()).isEqualTo(STANDARD_ON_DEMAND_VCPUS);
        assertThat(quota.quotaName())
                .isEqualTo("Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances");
        assertThat(quota.quotaArn()).isEqualTo(expectedArn);
        assertThat(quota.unit()).isEqualTo("None");
        assertThat(quota.adjustable()).isTrue();
        assertThat(quota.globalQuota()).isFalse();
        assertThat(quota.quotaAppliedAtLevel()).isEqualTo(AppliedLevelEnum.ACCOUNT);
    }
}
