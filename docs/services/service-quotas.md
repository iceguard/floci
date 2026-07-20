# Service Quotas

**Protocol:** JSON 1.1
**Endpoint:** `http://localhost:4566/`
**Target prefix:** `X-Amz-Target: ServiceQuotasV20190624.*`

Floci exposes a read-only Service Quotas catalog for modeled account-level
quotas. Elastic IP addresses per Region belong to Amazon EC2; NAT gateways per
Availability Zone belong to Amazon VPC. AWS-default operations return immutable
catalog defaults. Applied-quota operations return the configured local account
limit for Standard On-Demand vCPUs and the catalog default for other modeled
quotas. The catalog does not enforce allocation admission.

## Supported Actions

<!-- floci:actions:start -->
| Action | Description |
| --- | --- |
| `GetServiceQuota` | Returns one supported quota |
| `GetAWSDefaultServiceQuota` | Returns one supported default quota |
| `ListServiceQuotas` | Lists supported quotas for a service |
| `ListAWSDefaultServiceQuotas` | Lists supported default quotas for a service |
| `ListServices` | Lists services with supported quotas |
<!-- floci:actions:end -->

List operations accept `MaxResults` and `NextToken`. `ListServiceQuotas` also
supports `QuotaCode` and `QuotaAppliedAtLevel`; every modeled quota is applied
at the `ACCOUNT` level. Tokens are scoped to the operation, service, and filter
set that produced them.

The modeled quotas are account-level. `GetServiceQuota` rejects a supplied
resource `ContextId` with `NoSuchResourceException`; resource context is not
supported for these entries.

## Supported Quotas

| Service code | Quota code | Name | Default |
| --- | --- | --- | ---: |
| `ec2` | `L-0263D0A3` | Elastic IP addresses per Region | 5 |
| `ec2` | `L-1216C47A` | Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances | 5 vCPUs |
| `vpc` | `L-FE5A380F` | NAT gateways per Availability Zone | 5 |

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `FLOCI_SERVICES_SERVICEQUOTAS_ENABLED` | `true` | Enable or disable Service Quotas |
| `FLOCI_SERVICES_SERVICEQUOTAS_STANDARD_ON_DEMAND_VCPUS` | `5` | Applied account limit for EC2 Standard On-Demand vCPUs |
