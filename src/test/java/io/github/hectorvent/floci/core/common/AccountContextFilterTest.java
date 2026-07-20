package io.github.hectorvent.floci.core.common;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountContextFilterTest {

    private static final String DEFAULT_ACCOUNT = "000000000000";
    private static final String DEFAULT_REGION = "us-east-1";

    private AccountResolver accountResolver;
    private RegionResolver regionResolver;
    private RequestContext requestContext;
    private Map<String, String> sessionAccounts;
    private AccountContextFilter filter;

    @BeforeEach
    void setUp() {
        accountResolver = new AccountResolver(DEFAULT_ACCOUNT);
        regionResolver = new RegionResolver(DEFAULT_REGION, DEFAULT_ACCOUNT);
        requestContext = new RequestContext();
        sessionAccounts = new java.util.HashMap<>();
        SessionAccountLookup sessionLookup = (akid, token) -> {
            if (!"valid-token".equals(token) || !sessionAccounts.containsKey(akid)) {
                throw new AwsException("InvalidClientTokenId",
                        "The security token included in the request is invalid", 403);
            }
            return java.util.Optional.of(sessionAccounts.get(akid));
        };
        filter = new AccountContextFilter(accountResolver, regionResolver, requestContext, sessionLookup);
    }

    @Test
    void resolvesFromAuthHeaderWhenPresent() {
        ContainerRequestContext ctx = mockContext(
            "AWS4-HMAC-SHA256 Credential=000000000001/20260617/us-west-2/s3/aws4_request, SignedHeaders=host, Signature=abc",
            null
        );
        filter.filter(ctx);
        assertEquals("000000000001", requestContext.getAccountId());
        assertEquals("us-west-2", requestContext.getRegion());
    }

    @Test
    void resolvesFromPresignedCredentialWhenNoAuthHeader() {
        ContainerRequestContext ctx = mockContext(null,
            "000000000002/20260617/eu-west-1/s3/aws4_request");
        filter.filter(ctx);
        assertEquals("000000000002", requestContext.getAccountId());
        assertEquals("eu-west-1", requestContext.getRegion());
    }

    @Test
    void authHeaderTakesPrecedenceOverPresignedCredential() {
        ContainerRequestContext ctx = mockContext(
            "AWS4-HMAC-SHA256 Credential=000000000001/20260617/us-west-2/s3/aws4_request, SignedHeaders=host, Signature=abc",
            "000000000002/20260617/eu-west-1/s3/aws4_request"
        );
        filter.filter(ctx);
        assertEquals("000000000001", requestContext.getAccountId());
        assertEquals("us-west-2", requestContext.getRegion());
    }

    @Test
    void fallsBackToDefaultsWhenNoAuthInfo() {
        ContainerRequestContext ctx = mockContext(null, null);
        filter.filter(ctx);
        assertEquals(DEFAULT_ACCOUNT, requestContext.getAccountId());
        assertEquals(DEFAULT_REGION, requestContext.getRegion());
    }

    @Test
    void emptyAuthHeaderFallsBackToPresignedCredential() {
        ContainerRequestContext ctx = mockContext("",
            "000000000002/20260617/eu-west-1/s3/aws4_request");
        filter.filter(ctx);
        assertEquals("000000000002", requestContext.getAccountId());
        assertEquals("eu-west-1", requestContext.getRegion());
    }

    @Test
    void emptyPresignedCredentialFallsBackToDefaults() {
        ContainerRequestContext ctx = mockContext("", "");
        filter.filter(ctx);
        assertEquals(DEFAULT_ACCOUNT, requestContext.getAccountId());
        assertEquals(DEFAULT_REGION, requestContext.getRegion());
    }

    @Test
    void resolvesAssumedRoleSessionKeyToSessionAccount() {
        sessionAccounts.put("ASIAEXAMPLESESSIONKEY", "222233334444");
        ContainerRequestContext ctx = mockContext(
            "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLESESSIONKEY/20260617/us-west-2/dynamodb/aws4_request, "
                + "SignedHeaders=host, Signature=abc",
            null,
            "valid-token",
            null
        );
        filter.filter(ctx);
        assertEquals("222233334444", requestContext.getAccountId());
        assertEquals("us-west-2", requestContext.getRegion());
    }

    @Test
    void twelveDigitAkidWinsOverSessionLookup() {
        sessionAccounts.put("000000000001", "999999999999");
        ContainerRequestContext ctx = mockContext(
            "AWS4-HMAC-SHA256 Credential=000000000001/20260617/us-west-2/s3/aws4_request, "
                + "SignedHeaders=host, Signature=abc",
            null
        );
        filter.filter(ctx);
        assertEquals("000000000001", requestContext.getAccountId());
    }

    @Test
    void unknownSessionKeyFallsBackToDefault() {
        ContainerRequestContext ctx = mockContext(
            "AWS4-HMAC-SHA256 Credential=ASIAUNKNOWNKEY/20260617/us-west-2/s3/aws4_request, "
                + "SignedHeaders=host, Signature=abc",
            null
        );
        filter.filter(ctx);
        assertEquals(DEFAULT_ACCOUNT, requestContext.getAccountId());
        verify(ctx).abortWith(org.mockito.ArgumentMatchers.argThat(response -> response.getStatus() == 403));
    }

    @Test
    void resolvesSessionKeyFromPresignedCredential() {
        sessionAccounts.put("ASIAPRESIGNEDKEY", "555566667777");
        ContainerRequestContext ctx = mockContext(null,
            "ASIAPRESIGNEDKEY/20260617/eu-west-1/s3/aws4_request", null, "valid-token");
        filter.filter(ctx);
        assertEquals("555566667777", requestContext.getAccountId());
        assertEquals("eu-west-1", requestContext.getRegion());
    }

    private ContainerRequestContext mockContext(String authHeader, String xAmzCredential) {
        return mockContext(authHeader, xAmzCredential, null, null);
    }

    private ContainerRequestContext mockContext(String authHeader, String xAmzCredential,
                                                String headerToken, String queryToken) {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.getHeaderString("Authorization")).thenReturn(authHeader);
        when(ctx.getHeaderString("X-Amz-Security-Token")).thenReturn(headerToken);

        UriInfo uriInfo = mock(UriInfo.class);
        MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
        if (xAmzCredential != null) {
            queryParams.add("X-Amz-Credential", xAmzCredential);
        }
        if (queryToken != null) {
            queryParams.add("X-Amz-Security-Token", queryToken);
        }
        when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        when(ctx.getUriInfo()).thenReturn(uriInfo);

        return ctx;
    }
}
