package io.github.hectorvent.floci.services.iam.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionCredential {

    @RegisterForReflection
    public enum SessionType {
        ASSUME_ROLE,
        WEB_IDENTITY,
        SAML,
        FEDERATION_TOKEN,
        GET_SESSION_TOKEN
    }

    private String accessKeyId;
    private String secretAccessKey;
    private String sessionToken;
    private String roleArn;
    private String roleSessionName;
    private String targetAccountId;
    private String assumedRolePrincipalId;
    private Instant expiration;
    /** Inline session policy passed to AssumeRole/GetFederationToken — further restricts role policies. */
    private String sessionPolicyDocument;
    /**
     * Account of the caller that minted this session, captured at mint time. Used to route
     * temporary credentials that carry no role ARN (e.g. GetSessionToken) back to the caller.
     */
    private String originAccountId;
    /** Identity that requested credentials without assuming a new role, such as GetSessionToken. */
    private String sourcePrincipalArn;
    private String sourcePrincipalId;
    private SessionType sessionType;
    private boolean mfaAuthenticated;
    private boolean principalBindingRequired;

    public SessionCredential() {}

    public SessionCredential(String accessKeyId, String roleArn, Instant expiration) {
        this.accessKeyId = accessKeyId;
        this.roleArn = roleArn;
        this.expiration = expiration;
    }

    public SessionCredential(String accessKeyId, String roleArn, Instant expiration, String sessionPolicyDocument) {
        this.accessKeyId = accessKeyId;
        this.roleArn = roleArn;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String roleArn, Instant expiration,
                              String sessionPolicyDocument) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.roleArn = roleArn;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String roleArn, Instant expiration,
                              String sessionPolicyDocument, String originAccountId) {
        this(accessKeyId, secretAccessKey, null, roleArn, null, null, null,
                expiration, sessionPolicyDocument, originAccountId, null, null);
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String sessionToken,
                             String roleArn, String roleSessionName, String targetAccountId,
                             String assumedRolePrincipalId, Instant expiration,
                             String sessionPolicyDocument, String originAccountId) {
        this(accessKeyId, secretAccessKey, sessionToken, roleArn, roleSessionName,
                targetAccountId, assumedRolePrincipalId, expiration, sessionPolicyDocument,
                originAccountId, null, null);
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String sessionToken,
                             String roleArn, String roleSessionName, String targetAccountId,
                             String assumedRolePrincipalId, Instant expiration,
                             String sessionPolicyDocument, String originAccountId,
                             String sourcePrincipalArn, String sourcePrincipalId) {
        this(accessKeyId, secretAccessKey, sessionToken, roleArn, roleSessionName,
                targetAccountId, assumedRolePrincipalId, expiration, sessionPolicyDocument,
                originAccountId, sourcePrincipalArn, sourcePrincipalId, null, false, false);
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String sessionToken,
                             String roleArn, String roleSessionName, String targetAccountId,
                             String assumedRolePrincipalId, Instant expiration,
                             String sessionPolicyDocument, String originAccountId,
                             String sourcePrincipalArn, String sourcePrincipalId,
                             SessionType sessionType, boolean mfaAuthenticated,
                             boolean principalBindingRequired) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.sessionToken = sessionToken;
        this.roleArn = roleArn;
        this.roleSessionName = roleSessionName;
        this.targetAccountId = targetAccountId;
        this.assumedRolePrincipalId = assumedRolePrincipalId;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
        this.originAccountId = originAccountId;
        this.sourcePrincipalArn = sourcePrincipalArn;
        this.sourcePrincipalId = sourcePrincipalId;
        this.sessionType = sessionType;
        this.mfaAuthenticated = mfaAuthenticated;
        this.principalBindingRequired = principalBindingRequired;
    }

    public String getAccessKeyId() { return accessKeyId; }
    public void setAccessKeyId(String accessKeyId) { this.accessKeyId = accessKeyId; }

    public String getSecretAccessKey() { return secretAccessKey; }
    public void setSecretAccessKey(String secretAccessKey) { this.secretAccessKey = secretAccessKey; }

    public String getSessionToken() { return sessionToken; }
    public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }

    public String getRoleArn() { return roleArn; }
    public void setRoleArn(String roleArn) { this.roleArn = roleArn; }

    public String getRoleSessionName() { return roleSessionName; }
    public void setRoleSessionName(String roleSessionName) { this.roleSessionName = roleSessionName; }

    public String getTargetAccountId() { return targetAccountId; }
    public void setTargetAccountId(String targetAccountId) { this.targetAccountId = targetAccountId; }

    public String getAssumedRolePrincipalId() { return assumedRolePrincipalId; }
    public void setAssumedRolePrincipalId(String assumedRolePrincipalId) {
        this.assumedRolePrincipalId = assumedRolePrincipalId;
    }

    public Instant getExpiration() { return expiration; }
    public void setExpiration(Instant expiration) { this.expiration = expiration; }

    public String getSessionPolicyDocument() { return sessionPolicyDocument; }
    public void setSessionPolicyDocument(String sessionPolicyDocument) { this.sessionPolicyDocument = sessionPolicyDocument; }

    public String getOriginAccountId() { return originAccountId; }
    public void setOriginAccountId(String originAccountId) { this.originAccountId = originAccountId; }

    public String getSourcePrincipalArn() { return sourcePrincipalArn; }
    public void setSourcePrincipalArn(String sourcePrincipalArn) { this.sourcePrincipalArn = sourcePrincipalArn; }

    public String getSourcePrincipalId() { return sourcePrincipalId; }
    public void setSourcePrincipalId(String sourcePrincipalId) { this.sourcePrincipalId = sourcePrincipalId; }

    public SessionType getSessionType() { return sessionType; }
    public void setSessionType(SessionType sessionType) { this.sessionType = sessionType; }

    public boolean isMfaAuthenticated() { return mfaAuthenticated; }
    public void setMfaAuthenticated(boolean mfaAuthenticated) { this.mfaAuthenticated = mfaAuthenticated; }

    public boolean isPrincipalBindingRequired() { return principalBindingRequired; }
    public void setPrincipalBindingRequired(boolean principalBindingRequired) {
        this.principalBindingRequired = principalBindingRequired;
    }
}
