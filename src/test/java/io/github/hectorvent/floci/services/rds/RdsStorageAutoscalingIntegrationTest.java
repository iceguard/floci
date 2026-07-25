package io.github.hectorvent.floci.services.rds;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.rds.model.DBInstance;
import software.amazon.awssdk.services.rds.model.RdsException;
import software.amazon.awssdk.services.rds.model.ValidStorageOptions;

import java.net.URI;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class RdsStorageAutoscalingIntegrationTest {

    private static final String REGION = "us-east-1";

    @Test
    void sdkReportsGp3OrderabilityAndValidStorageGrowth() {
        try (RdsClient rds = rdsClient()) {
            var options = rds.describeOrderableDBInstanceOptions(request -> request
                            .engine("postgres")
                            .engineVersion("16.14")
                            .dbInstanceClass("db.t4g.small"))
                    .orderableDBInstanceOptions();

            assertEquals(1, options.size());
            var option = options.getFirst();
            assertEquals("gp3", option.storageType());
            assertEquals(Boolean.TRUE, option.supportsStorageAutoscaling());
            assertTrue(option.minStorageSize() <= 20);
            assertTrue(option.maxStorageSize() >= 100);
        }
    }

    @Test
    void sdkRoundTripsStorageAutoscalingAndRejectsStateRegression() {
        String id = "rds-storage-" + UUID.randomUUID().toString().substring(0, 8);
        try (RdsClient rds = rdsClient()) {
            DBInstance created = rds.createDBInstance(request -> request
                            .dbInstanceIdentifier(id)
                            .dbInstanceClass("db.t4g.small")
                            .engine("postgres")
                            .engineVersion("16.14")
                            .masterUsername("admin")
                            .masterUserPassword("secret123")
                            .allocatedStorage(20)
                            .maxAllocatedStorage(100)
                            .storageType("gp3"))
                    .dbInstance();
            assertStorage(created, 20, 100);

            DBInstance described = rds.describeDBInstances(request -> request.dbInstanceIdentifier(id))
                    .dbInstances()
                    .getFirst();
            assertStorage(described, 20, 100);

            ValidStorageOptions gp3 = rds.describeValidDBInstanceModifications(
                            request -> request.dbInstanceIdentifier(id))
                    .validDBInstanceModificationsMessage()
                    .storage()
                    .stream()
                    .filter(option -> "gp3".equals(option.storageType()))
                    .findFirst()
                    .orElseThrow();
            assertEquals(Boolean.TRUE, gp3.supportsStorageAutoscaling());
            assertEquals(1, gp3.storageSize().size());
            assertTrue(gp3.storageSize().getFirst().from() > 20);
            assertTrue(gp3.storageSize().getFirst().from() <= 30);
            assertTrue(gp3.storageSize().getFirst().to() >= 100);
            assertEquals(1, gp3.storageSize().getFirst().step());

            assertStorage(rds.modifyDBInstance(request -> request
                    .dbInstanceIdentifier(id)
                    .allocatedStorage(30)).dbInstance(), 30, 100);
            assertStorage(rds.modifyDBInstance(request -> request
                    .dbInstanceIdentifier(id)
                    .maxAllocatedStorage(100)).dbInstance(), 30, 100);
            assertStorage(rds.modifyDBInstance(request -> request
                    .dbInstanceIdentifier(id)
                    .maxAllocatedStorage(120)).dbInstance(), 30, 120);

            DBInstance disabled = rds.modifyDBInstance(request -> request
                    .dbInstanceIdentifier(id)
                    .maxAllocatedStorage(0)).dbInstance();
            assertEquals(30, disabled.allocatedStorage());
            assertNull(disabled.maxAllocatedStorage());

            assertStorage(rds.modifyDBInstance(request -> request
                    .dbInstanceIdentifier(id)
                    .maxAllocatedStorage(100)).dbInstance(), 30, 100);

            assertInvalidStorageChange(assertThrows(RdsException.class,
                    () -> rds.modifyDBInstance(request -> request
                            .dbInstanceIdentifier(id)
                            .allocatedStorage(20))));
            assertInvalidStorageChange(assertThrows(RdsException.class,
                    () -> rds.modifyDBInstance(request -> request
                            .dbInstanceIdentifier(id)
                            .maxAllocatedStorage(25))));

            DBInstance retained = rds.describeDBInstances(request -> request.dbInstanceIdentifier(id))
                    .dbInstances()
                    .getFirst();
            assertStorage(retained, 30, 100);
        } finally {
            try (RdsClient rds = rdsClient()) {
                try {
                    rds.deleteDBInstance(request -> request
                            .dbInstanceIdentifier(id)
                            .skipFinalSnapshot(true));
                } catch (RdsException ignored) {
                    // Creation can fail in the parent-red run before an instance exists.
                }
            }
        }
    }

    private static RdsClient rdsClient() {
        return RdsClient.builder()
                .endpointOverride(URI.create("http://localhost:" + RestAssured.port))
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .region(Region.of(REGION))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("000000000000", "test-secret-key")))
                .build();
    }

    private static void assertStorage(DBInstance instance, int allocated, int maximum) {
        assertEquals(allocated, instance.allocatedStorage());
        assertEquals(maximum, instance.maxAllocatedStorage());
        assertEquals("gp3", instance.storageType());
    }

    private static void assertInvalidStorageChange(RdsException exception) {
        assertEquals(400, exception.statusCode());
        assertEquals("InvalidParameterCombination", exception.awsErrorDetails().errorCode());
        assertNotNull(exception.requestId());
    }
}
