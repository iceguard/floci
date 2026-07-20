package io.github.hectorvent.floci.services.servicequotas;

import io.github.hectorvent.floci.config.EmulatorConfig;

import java.util.List;
import java.util.Optional;
import java.util.OptionalDouble;

public final class ServiceQuotaCatalog {

    public static final String EC2_SERVICE_CODE = "ec2";
    public static final String EC2_SERVICE_NAME = "Amazon Elastic Compute Cloud (Amazon EC2)";
    public static final String VPC_SERVICE_CODE = "vpc";
    public static final String VPC_SERVICE_NAME = "Amazon Virtual Private Cloud (Amazon VPC)";
    public static final String EIP_PER_REGION = "L-0263D0A3";
    public static final String STANDARD_ON_DEMAND_VCPUS = "L-1216C47A";
    public static final String NAT_GATEWAYS_PER_AVAILABILITY_ZONE = "L-FE5A380F";
    public static final String ACCOUNT_LEVEL = "ACCOUNT";
    public static final double AWS_DEFAULT_STANDARD_ON_DEMAND_VCPUS = 5;

    private static final List<ServiceDefinition> SERVICES = List.of(
            new ServiceDefinition(EC2_SERVICE_CODE, EC2_SERVICE_NAME, List.of(
                    new QuotaDefinition(EIP_PER_REGION, "Elastic IP addresses per Region",
                            5, true, false, ACCOUNT_LEVEL),
                    new QuotaDefinition(STANDARD_ON_DEMAND_VCPUS,
                            "Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances",
                            AWS_DEFAULT_STANDARD_ON_DEMAND_VCPUS, true, false, ACCOUNT_LEVEL))),
            new ServiceDefinition(VPC_SERVICE_CODE, VPC_SERVICE_NAME, List.of(
                    new QuotaDefinition(NAT_GATEWAYS_PER_AVAILABILITY_ZONE,
                            "NAT gateways per Availability Zone", 5, true, false, ACCOUNT_LEVEL))));

    private ServiceQuotaCatalog() {}

    public static List<ServiceDefinition> services() {
        return SERVICES;
    }

    public static Optional<ServiceDefinition> service(String serviceCode) {
        return SERVICES.stream()
                .filter(service -> service.code().equals(serviceCode))
                .findFirst();
    }

    public static List<QuotaDefinition> forService(String serviceCode) {
        return service(serviceCode).map(ServiceDefinition::quotas).orElseGet(List::of);
    }

    public static Optional<QuotaDefinition> find(String serviceCode, String quotaCode) {
        return forService(serviceCode).stream()
                .filter(quota -> quota.code().equals(quotaCode))
                .findFirst();
    }

    /** Resolves the locally applied value while preserving the catalog's AWS default. */
    public static OptionalDouble appliedValue(EmulatorConfig.ServiceQuotasServiceConfig config,
                                              String serviceCode,
                                              String quotaCode) {
        return find(serviceCode, quotaCode)
                .map(quota -> EC2_SERVICE_CODE.equals(serviceCode)
                        && STANDARD_ON_DEMAND_VCPUS.equals(quotaCode)
                                ? (double) config.standardOnDemandVcpus()
                                : quota.awsDefaultValue())
                .stream()
                .mapToDouble(Double::doubleValue)
                .findFirst();
    }

    public record ServiceDefinition(String code, String name, List<QuotaDefinition> quotas) {}

    public record QuotaDefinition(String code,
                                  String name,
                                  double awsDefaultValue,
                                  boolean adjustable,
                                  boolean global,
                                  String appliedAtLevel) {}
}
