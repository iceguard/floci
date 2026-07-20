package io.github.hectorvent.floci.core.common;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

import java.util.Optional;

/**
 * Populates {@link RequestContext} with the account ID and region derived from
 * the incoming AWS Authorization header or, for presigned URL requests, the
 * X-Amz-Credential query parameter. Runs at AUTHENTICATION priority so that
 * downstream filters (e.g. IAM enforcement) can rely on the context being set.
 *
 * <p>Account resolution precedence: a 12-digit access key ID is used directly as
 * the account; otherwise temporary credentials (e.g. assumed-role {@code ASIA...}
 * keys) must authenticate against the session store via {@link SessionAccountLookup}.
 * Other credential shapes retain the configured default-account fallback.
 *
 * <p>This authenticates the stored temporary access-key/session-token tuple. General
 * control-plane verification of the secret-derived SigV4 signature is a separate capability.
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION - 100)
public class AccountContextFilter implements ContainerRequestFilter {

    private final AccountResolver accountResolver;
    private final RegionResolver regionResolver;
    private final RequestContext requestContext;
    private final SessionAccountLookup sessionAccountLookup;

    @Inject
    public AccountContextFilter(AccountResolver accountResolver,
                                RegionResolver regionResolver,
                                RequestContext requestContext,
                                SessionAccountLookup sessionAccountLookup) {
        this.accountResolver = accountResolver;
        this.regionResolver = regionResolver;
        this.requestContext = requestContext;
        this.sessionAccountLookup = sessionAccountLookup;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        String auth = ctx.getHeaderString("Authorization");
        if (auth != null && !auth.isEmpty()) {
            String akid = accountResolver.extractAccessKeyId(auth);
            requestContext.setAccountId(resolveAccount(
                    ctx, akid, securityToken(ctx), accountResolver.resolve(auth), credentialScope(auth)));
            requestContext.setRegion(regionResolver.resolveRegionFromAuth(auth));
        } else {
            String credential = ctx.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
            if (credential != null && !credential.isEmpty()) {
                String akid = accountResolver.extractPresignedAccessKeyId(credential);
                requestContext.setAccountId(resolveAccount(
                        ctx, akid, querySecurityToken(ctx),
                        accountResolver.resolveFromPresignedCredential(credential),
                        credentialScope(credential)));
                requestContext.setRegion(regionResolver.resolveRegionFromPresignedCredential(credential));
            } else {
                requestContext.setAccountId(accountResolver.resolve(null));
                requestContext.setRegion(regionResolver.resolveRegionFromAuth(null));
            }
        }
    }

    /**
     * Applies the account-resolution precedence. A 12-digit AKID is already reflected in
     * {@code resolvedDefault} (the account or default returned by {@link AccountResolver});
     * for any other key shape, a live session lookup takes precedence before falling back.
     */
    private String resolveAccount(ContainerRequestContext ctx, String akid, String sessionToken,
                                  String resolvedDefault, String credentialScope) {
        if (isTemporaryAccessKey(akid)) {
            try {
                return sessionAccountLookup.resolveAccountId(akid, sessionToken)
                        .orElseThrow(() -> invalidSessionToken());
            } catch (AwsException e) {
                ctx.abortWith(IamEnforcementFilter.awsErrorResponse(
                        e.getErrorCode(), e.getMessage(), credentialScope, ctx.getMediaType()));
                return resolvedDefault;
            }
        }
        return resolvedDefault;
    }

    private static boolean isTemporaryAccessKey(String accessKeyId) {
        return accessKeyId != null && accessKeyId.startsWith("ASIA");
    }

    private static AwsException invalidSessionToken() {
        return new AwsException("InvalidClientTokenId",
                "The security token included in the request is invalid", 403);
    }

    private static String securityToken(ContainerRequestContext ctx) {
        return ctx.getHeaderString("X-Amz-Security-Token");
    }

    private static String querySecurityToken(ContainerRequestContext ctx) {
        return ctx.getUriInfo().getQueryParameters().getFirst("X-Amz-Security-Token");
    }

    private static String credentialScope(String credential) {
        if (credential == null) {
            return null;
        }
        int requestIndex = credential.indexOf("/aws4_request");
        if (requestIndex < 0) {
            return null;
        }
        int serviceStart = credential.lastIndexOf('/', requestIndex - 1) + 1;
        return serviceStart > 0 ? credential.substring(serviceStart, requestIndex) : null;
    }
}
