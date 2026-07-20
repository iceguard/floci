package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.autoscaling.AutoScalingService;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IamConditionContextResolverTest {

    private final IamConditionContextResolver resolver =
            new IamConditionContextResolver(
                    new AwsFormRequestResolver(), mock(AutoScalingService.class));

    @Test
    void resolvesS3ListBucketQueryConditionContext() {
        ContainerRequestContext containerRequest = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("prefix", "my_namespace/table/");
        query.add("delimiter", "/");
        query.add("max-keys", "100");

        when(containerRequest.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getQueryParameters()).thenReturn(query);

        Map<String, List<String>> conditions =
                resolver.resolve("s3", "s3:ListBucket", containerRequest, "us-east-1");

        assertEquals(List.of("my_namespace/table/"), conditions.get("s3:prefix"));
        assertEquals(List.of("/"), conditions.get("s3:delimiter"));
        assertEquals(List.of("100"), conditions.get("s3:max-keys"));
    }

    @Test
    void s3BucketListConditionContextReturnsNullWhenNoSupportedQueryParametersArePresent() {
        assertNull(resolver.s3BucketListConditionContext(new MultivaluedHashMap<>()));
    }

    @Test
    void resolveReturnsNullForUnsupportedServiceOrAction() {
        ContainerRequestContext containerRequest = mock(ContainerRequestContext.class);

        assertNull(resolver.resolve("lambda", "lambda:InvokeFunction", containerRequest, "us-east-1"));
        assertNull(resolver.resolve("s3", "s3:GetObject", containerRequest, "us-east-1"));
    }
}
