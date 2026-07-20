package io.github.hectorvent.floci.services.cloudformation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CloudFormationResourceRegistry;
import io.github.hectorvent.floci.services.rds.RdsService;
import io.github.hectorvent.floci.services.rds.model.DbParameterGroup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Function;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CloudFormationResourceProvisionerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private RdsService rdsService;
    private CloudFormationResourceProvisioner provisioner;

    @BeforeEach
    void setUp() {
        rdsService = mock(RdsService.class);
        provisioner = new CloudFormationResourceProvisioner(
                null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null,
                mapper,
                null, null, null, null, null, null, null,
                rdsService, null, null, null, null, null, null,
                new CloudFormationResourceRegistry(java.util.List.of()));
    }

    @Test
    void createsDbParameterGroupInStackRegion() throws Exception {
        DbParameterGroup group = mock(DbParameterGroup.class);
        when(group.getDbParameterGroupName()).thenReturn("west-parameters");
        when(rdsService.createDbParameterGroup(any(), any(), any(), any(), anyMap()))
                .thenReturn(group);
        CloudFormationTemplateEngine engine = new CloudFormationTemplateEngine(
                "000000000000", "us-west-2", "west-stack", "stack/id",
                Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), mapper,
                (Function<String, String>) name -> null);

        provisioner.provision(
                "DbParameters",
                "AWS::RDS::DBParameterGroup",
                mapper.readTree("""
                        {"DBParameterGroupName":"west-parameters","Family":"postgres18",
                         "Description":"west parameters"}
                        """),
                engine,
                "us-west-2",
                "000000000000",
                "west-stack");

        verify(rdsService).createDbParameterGroup(
                "west-parameters", "postgres18", "west parameters", "us-west-2", Map.of());
    }

    @Test
    void deletesRdsGroupsInStackRegion() {
        provisioner.delete("AWS::RDS::DBSubnetGroup", "west-subnets", "us-west-2");
        provisioner.delete("AWS::RDS::DBParameterGroup", "west-parameters", "us-west-2");

        verify(rdsService).deleteDbSubnetGroup("west-subnets", "us-west-2");
        verify(rdsService).deleteDbParameterGroup("west-parameters", "us-west-2");
    }
}
