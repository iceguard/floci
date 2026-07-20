package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.SessionAccountLookup;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.iam.model.AccessKey;
import io.github.hectorvent.floci.services.iam.model.IamGroup;
import io.github.hectorvent.floci.services.iam.model.IamPolicy;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.IamUser;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import io.github.hectorvent.floci.services.iam.model.PolicyVersion;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.SessionCredential;
import io.github.hectorvent.floci.services.iam.model.SessionCredential.SessionType;
import com.fasterxml.jackson.core.type.TypeReference;
import io.quarkus.runtime.Startup;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Core IAM business logic — users, groups, roles, policies, access keys, instance profiles.
 * IAM is a global service: resources are not region-scoped and storage keys have no region prefix.
 *
 * <p>Eagerly initialized at startup so AWS-managed policies (and the optional deployer principal)
 * are seeded under the default account before any request runs. Seeding is account-namespaced via
 * the request context, so deferring it to the first request would otherwise bind the seed data to
 * whichever account happened to make that call — a real hazard now that {@code AccountContextFilter}
 * resolves the request account through this service.
 */
@Startup
@ApplicationScoped
public class IamService implements SessionAccountLookup {

    private static final Logger LOG = Logger.getLogger(IamService.class);
    private static final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final String TEMPORARY_ACCESS_KEY_PREFIX = "ASIA";
    private static final String DEFAULT_DEPLOYER_USER = "floci-deployer";
    private static final String DEFAULT_DEPLOYER_ACCESS_KEY_ID = "floci";
    private static final String DEFAULT_DEPLOYER_SECRET_ACCESS_KEY = "floci";
    private static final int ROLE_INLINE_POLICY_SIZE_LIMIT = 10_240;

    private final StorageBackend<String, IamUser> users;
    private final StorageBackend<String, IamGroup> groups;
    private final StorageBackend<String, IamRole> roles;
    private final StorageBackend<String, IamPolicy> policies;
    private final StorageBackend<String, AccessKey> accessKeys;
    private final StorageBackend<String, InstanceProfile> instanceProfiles;
    private final StorageBackend<String, SessionCredential> sessions;
    private final RegionResolver regionResolver;
    private final boolean seedDeployerPrincipal;

    /**
     * AWS-managed policies (arn:aws:iam::aws:policy/...), keyed by ARN. These are global —
     * not owned by any account — so they live here rather than in the account-partitioned
     * {@link #policies} store, and {@link #getPolicy} resolves them for any caller.
     */
    private final Map<String, IamPolicy> awsManagedPolicies = buildAwsManagedPolicies();

    @Inject
    public IamService(StorageFactory storageFactory, EmulatorConfig config, RegionResolver regionResolver) {
        this(
            storageFactory.create("iam", "iam-users.json", new TypeReference<>() {}),
            storageFactory.create("iam", "iam-groups.json", new TypeReference<>() {}),
            storageFactory.create("iam", "iam-roles.json", new TypeReference<>() {}),
            storageFactory.create("iam", "iam-policies.json", new TypeReference<>() {}),
            storageFactory.create("iam", "iam-access-keys.json", new TypeReference<>() {}),
            storageFactory.create("iam", "iam-instance-profiles.json", new TypeReference<>() {}),
            storageFactory.create("iam", "iam-sessions.json", new TypeReference<>() {}),
            regionResolver,
            config.services().iam().seedDeployerPrincipal()
        );
    }

    IamService(StorageBackend<String, IamUser> users,
               StorageBackend<String, IamGroup> groups,
               StorageBackend<String, IamRole> roles,
               StorageBackend<String, IamPolicy> policies,
               StorageBackend<String, AccessKey> accessKeys,
               StorageBackend<String, InstanceProfile> instanceProfiles,
               StorageBackend<String, SessionCredential> sessions,
               RegionResolver regionResolver) {
        this(users, groups, roles, policies, accessKeys, instanceProfiles, sessions, regionResolver, false);
    }

    IamService(StorageBackend<String, IamUser> users,
               StorageBackend<String, IamGroup> groups,
               StorageBackend<String, IamRole> roles,
               StorageBackend<String, IamPolicy> policies,
               StorageBackend<String, AccessKey> accessKeys,
               StorageBackend<String, InstanceProfile> instanceProfiles,
               StorageBackend<String, SessionCredential> sessions,
               RegionResolver regionResolver,
               boolean seedDeployerPrincipal) {
        this.users = users;
        this.groups = groups;
        this.roles = roles;
        this.policies = policies;
        this.accessKeys = accessKeys;
        this.instanceProfiles = instanceProfiles;
        this.sessions = sessions;
        this.regionResolver = regionResolver;
        this.seedDeployerPrincipal = seedDeployerPrincipal;
    }

    @PostConstruct
    void seedDefaults() {
        seedAwsManagedPolicies();
        if (seedDeployerPrincipal) {
            seedDefaultDeployerPrincipal();
        }
    }

    private static Map<String, IamPolicy> buildAwsManagedPolicies() {
        Map<String, IamPolicy> catalog = new LinkedHashMap<>();
        for (AwsManagedPolicies.ManagedPolicyDef def : AwsManagedPolicies.POLICIES) {
            String arn = def.arn();
            catalog.put(arn, new IamPolicy("ANPA" + randomId(16), def.name(), def.path(), arn,
                    def.description(), AwsManagedPolicies.PERMISSIVE_DOCUMENT));
        }
        return catalog;
    }

    void seedAwsManagedPolicies() {
        // Managed policies are served globally from the catalog (see getPolicy); this also
        // mirrors them into the default-account store so ListPolicies(Scope=AWS) lists them.
        int seeded = 0;
        for (Map.Entry<String, IamPolicy> entry : awsManagedPolicies.entrySet()) {
            if (policies.get(entry.getKey()).isPresent()) {
                continue;
            }
            policies.put(entry.getKey(), entry.getValue());
            seeded++;
        }
        if (seeded > 0) {
            LOG.infov("Seeded {0} AWS managed policies", seeded);
        }
    }

    private void seedDefaultDeployerPrincipal() {
        String adminPolicyArn = AwsManagedPolicies.ARN_PREFIX + "/AdministratorAccess";
        IamUser user = users.get(DEFAULT_DEPLOYER_USER)
                .orElseGet(() -> {
                    String userId = "AIDA" + randomId(16);
                    String arn = iamArn("user", "/", DEFAULT_DEPLOYER_USER);
                    IamUser seededUser = new IamUser(userId, DEFAULT_DEPLOYER_USER, "/", arn);
                    users.put(DEFAULT_DEPLOYER_USER, seededUser);
                    LOG.infov("Seeded default IAM deployer user: {0}", DEFAULT_DEPLOYER_USER);
                    return seededUser;
                });
        if (!user.getAttachedPolicyArns().contains(adminPolicyArn)) {
            user.getAttachedPolicyArns().add(adminPolicyArn);
            users.put(DEFAULT_DEPLOYER_USER, user);
        }
        if (accessKeys.get(DEFAULT_DEPLOYER_ACCESS_KEY_ID).isEmpty()) {
            accessKeys.put(DEFAULT_DEPLOYER_ACCESS_KEY_ID, new AccessKey(
                    DEFAULT_DEPLOYER_ACCESS_KEY_ID,
                    DEFAULT_DEPLOYER_SECRET_ACCESS_KEY,
                    DEFAULT_DEPLOYER_USER));
            LOG.infov("Seeded default IAM deployer access key: {0}", DEFAULT_DEPLOYER_ACCESS_KEY_ID);
        }
    }

    // =========================================================================
    // Users
    // =========================================================================

    public IamUser createUser(String userName, String path) {
        if (users.get(userName).isPresent()) {
            throw new AwsException("EntityAlreadyExists",
                    "User with name " + userName + " already exists.", 409);
        }
        String userId = "AIDA" + randomId(16);
        String normalizedPath = normalizePath(path);
        String arn = iamArn("user", normalizedPath, userName);
        IamUser user = new IamUser(userId, userName, normalizedPath, arn);
        users.put(userName, user);
        LOG.infov("Created IAM user: {0}", userName);
        return user;
    }

    public IamUser getUser(String userName) {
        if (userName == null) {
            throw new AwsException("NoSuchEntity",
                    "The user with name null cannot be found.", 404);
        }
        return users.get(userName)
                .orElseThrow(() -> new AwsException("NoSuchEntity",
                        "The user with name " + userName + " cannot be found.", 404));
    }

    /** The IAM user that owns the given access key id, when it is a real stored key. */
    public Optional<String> findUserNameByAccessKeyId(String accessKeyId) {
        if (accessKeyId == null) {
            return Optional.empty();
        }
        return accessKeys.get(accessKeyId).map(AccessKey::getUserName);
    }

    public void deleteUser(String userName) {
        IamUser user = getUser(userName);
        if (!user.getAttachedPolicyArns().isEmpty()) {
            throw new AwsException("DeleteConflict",
                    "Cannot delete entity, must detach all policies first.", 409);
        }
        if (!user.getGroupNames().isEmpty()) {
            throw new AwsException("DeleteConflict",
                    "Cannot delete entity, must remove from all groups first.", 409);
        }
        users.delete(userName);
        LOG.infov("Deleted IAM user: {0}", userName);
    }

    public List<IamUser> listUsers(String pathPrefix) {
        String prefix = pathPrefix != null ? pathPrefix : "/";
        return users.scan(k -> true).stream()
                .filter(u -> u.getPath().startsWith(prefix))
                .toList();
    }

    public void updateUser(String userName, String newUserName, String newPath) {
        IamUser user = getUser(userName);
        if (newUserName != null && !newUserName.equals(userName)) {
            if (users.get(newUserName).isPresent()) {
                throw new AwsException("EntityAlreadyExists",
                        "User with name " + newUserName + " already exists.", 409);
            }
            users.delete(userName);
            user.setUserName(newUserName);
            if (newPath != null) user.setPath(normalizePath(newPath));
            user.setArn(iamArn("user", user.getPath(), newUserName));
            users.put(newUserName, user);
        } else {
            if (newPath != null) {
                user.setPath(normalizePath(newPath));
                user.setArn(iamArn("user", user.getPath(), userName));
            }
            users.put(userName, user);
        }
    }

    public void tagUser(String userName, Map<String, String> newTags) {
        IamUser user = getUser(userName);
        user.getTags().putAll(newTags);
        users.put(userName, user);
    }

    public void untagUser(String userName, List<String> tagKeys) {
        IamUser user = getUser(userName);
        tagKeys.forEach(user.getTags()::remove);
        users.put(userName, user);
    }

    public Map<String, String> listUserTags(String userName) {
        return getUser(userName).getTags();
    }

    // =========================================================================
    // Groups
    // =========================================================================

    public IamGroup createGroup(String groupName, String path) {
        if (groups.get(groupName).isPresent()) {
            throw new AwsException("EntityAlreadyExists",
                    "Group with name " + groupName + " already exists.", 409);
        }
        String groupId = "AGPA" + randomId(16);
        String normalizedPath = normalizePath(path);
        String arn = iamArn("group", normalizedPath, groupName);
        IamGroup group = new IamGroup(groupId, groupName, normalizedPath, arn);
        groups.put(groupName, group);
        LOG.infov("Created IAM group: {0}", groupName);
        return group;
    }

    public IamGroup getGroup(String groupName) {
        return groups.get(groupName)
                .orElseThrow(() -> new AwsException("NoSuchEntity",
                        "The group with name " + groupName + " cannot be found.", 404));
    }

    public void deleteGroup(String groupName) {
        IamGroup group = getGroup(groupName);
        if (!group.getAttachedPolicyArns().isEmpty() || !group.getInlinePolicies().isEmpty()) {
            throw new AwsException("DeleteConflict",
                    "Cannot delete entity, must detach all policies first.", 409);
        }
        if (!group.getUserNames().isEmpty()) {
            throw new AwsException("DeleteConflict",
                    "Cannot delete entity, must remove all users from group first.", 409);
        }
        groups.delete(groupName);
        LOG.infov("Deleted IAM group: {0}", groupName);
    }

    public List<IamGroup> listGroups(String pathPrefix) {
        String prefix = pathPrefix != null ? pathPrefix : "/";
        return groups.scan(k -> true).stream()
                .filter(g -> g.getPath().startsWith(prefix))
                .toList();
    }

    public void addUserToGroup(String groupName, String userName) {
        IamGroup group = getGroup(groupName);
        IamUser user = getUser(userName);
        if (!group.getUserNames().contains(userName)) {
            group.getUserNames().add(userName);
            groups.put(groupName, group);
        }
        if (!user.getGroupNames().contains(groupName)) {
            user.getGroupNames().add(groupName);
            users.put(userName, user);
        }
    }

    public void removeUserFromGroup(String groupName, String userName) {
        IamGroup group = getGroup(groupName);
        IamUser user = getUser(userName);
        group.getUserNames().remove(userName);
        groups.put(groupName, group);
        user.getGroupNames().remove(groupName);
        users.put(userName, user);
    }

    public List<IamGroup> listGroupsForUser(String userName) {
        IamUser user = getUser(userName);
        return user.getGroupNames().stream()
                .flatMap(gn -> groups.get(gn).stream())
                .toList();
    }

    // =========================================================================
    // Roles
    // =========================================================================

    public IamRole createRole(String roleName, String path, String assumeRolePolicyDocument,
                              String description, int maxSessionDuration, Map<String, String> tags) {
        if (roles.get(roleName).isPresent()) {
            throw new AwsException("EntityAlreadyExists",
                    "Role with name " + roleName + " already exists.", 409);
        }
        String roleId = "AROA" + randomId(16);
        String normalizedPath = normalizePath(path);
        String arn = iamArn("role", normalizedPath, roleName);
        IamRole role = new IamRole(roleId, roleName, normalizedPath, arn, assumeRolePolicyDocument);
        role.setDescription(description);
        if (maxSessionDuration > 0) role.setMaxSessionDuration(maxSessionDuration);
        if (tags != null) role.getTags().putAll(tags);
        roles.put(roleName, role);
        LOG.infov("Created IAM role: {0}", roleName);
        return role;
    }

    public IamRole getRole(String roleName) {
        return roles.get(roleName)
                .orElseThrow(() -> new AwsException("NoSuchEntity",
                        "The role with name " + roleName + " cannot be found.", 404));
    }

    /**
     * Looks up a role by name in a specific account's namespace, without throwing when absent.
     *
     * <p>Roles are account-namespaced, so a cross-account caller (e.g. STS AssumeRole) must resolve
     * the role in its owning account — taken from the role ARN — rather than the request's account.
     */
    public Optional<IamRole> findRole(String accountId, String roleName) {
        if (roles instanceof AccountAwareStorageBackend<IamRole> aware) {
            return aware.getForAccount(accountId, roleName);
        }
        return roles.get(roleName);
    }

    public void deleteRole(String roleName) {
        IamRole role = getRole(roleName);
        if (!role.getAttachedPolicyArns().isEmpty() || !role.getInlinePolicies().isEmpty()) {
            throw new AwsException("DeleteConflict",
                    "Cannot delete entity, must detach all policies first.", 409);
        }
        roles.delete(roleName);
        LOG.infov("Deleted IAM role: {0}", roleName);
    }

    public List<IamRole> listRoles(String pathPrefix) {
        String prefix = pathPrefix != null ? pathPrefix : "/";
        return roles.scan(k -> true).stream()
                .filter(r -> r.getPath().startsWith(prefix))
                .toList();
    }

    public void updateRole(String roleName, String description, int maxSessionDuration) {
        IamRole role = getRole(roleName);
        if (description != null) role.setDescription(description);
        if (maxSessionDuration > 0) role.setMaxSessionDuration(maxSessionDuration);
        roles.put(roleName, role);
    }

    public void updateAssumeRolePolicy(String roleName, String policyDocument) {
        IamRole role = getRole(roleName);
        role.setAssumeRolePolicyDocument(policyDocument);
        roles.put(roleName, role);
    }

    public void tagRole(String roleName, Map<String, String> newTags) {
        IamRole role = getRole(roleName);
        role.getTags().putAll(newTags);
        roles.put(roleName, role);
    }

    public void untagRole(String roleName, List<String> tagKeys) {
        IamRole role = getRole(roleName);
        tagKeys.forEach(role.getTags()::remove);
        roles.put(roleName, role);
    }

    public Map<String, String> listRoleTags(String roleName) {
        return getRole(roleName).getTags();
    }

    // =========================================================================
    // Managed Policies
    // =========================================================================

    public IamPolicy createPolicy(String policyName, String path, String description,
                                  String document, Map<String, String> tags) {
        String normalizedPath = normalizePath(path);
        String arn = iamArn("policy", normalizedPath, policyName);
        if (policies.get(arn).isPresent()) {
            throw new AwsException("EntityAlreadyExists",
                    "Policy " + arn + " already exists.", 409);
        }
        String policyId = "ANPA" + randomId(16);
        IamPolicy policy = new IamPolicy(policyId, policyName, normalizedPath, arn, description, document);
        if (tags != null) policy.getTags().putAll(tags);
        policies.put(arn, policy);
        LOG.infov("Created IAM policy: {0}", arn);
        return policy;
    }

    public IamPolicy getPolicy(String policyArn) {
        // AWS-managed policies (arn:aws:iam::aws:policy/...) are global — not owned by any
        // account — so they are served from the catalog rather than the account-partitioned
        // store, which would otherwise make them visible only to the default account.
        if (policyArn != null && policyArn.startsWith(AwsManagedPolicies.ARN_PREFIX)) {
            IamPolicy managed = awsManagedPolicies.get(policyArn);
            if (managed != null) {
                return managed;
            }
            throw new AwsException("NoSuchEntity", "Policy " + policyArn + " does not exist.", 404);
        }
        return policies.get(policyArn)
                .orElseThrow(() -> new AwsException("NoSuchEntity",
                        "Policy " + policyArn + " does not exist.", 404));
    }

    /**
     * Resolves a policy by ARN without throwing, mirroring {@link #getPolicy} so that
     * AWS-managed policies (arn:aws:iam::aws:policy/...) are served from the global catalog
     * rather than the account-partitioned store. Attached-policy read paths must use this:
     * a managed policy attached to a principal owned by a non-default account is absent from
     * that account's {@link #policies} partition and would otherwise be silently dropped.
     */
    private Optional<IamPolicy> resolvePolicy(String arn) {
        if (arn != null && arn.startsWith(AwsManagedPolicies.ARN_PREFIX)) {
            return Optional.ofNullable(awsManagedPolicies.get(arn));
        }
        return policies.get(arn);
    }

    private void rejectIfAwsManaged(String policyArn) {
        if (policyArn != null && policyArn.startsWith(AwsManagedPolicies.ARN_PREFIX)) {
            throw new AwsException("AccessDenied",
                    "Cannot modify or delete AWS managed policy: " + policyArn, 403);
        }
    }

    public void deletePolicy(String policyArn) {
        rejectIfAwsManaged(policyArn);
        IamPolicy policy = getPolicy(policyArn);
        if (policy.getAttachmentCount() > 0) {
            throw new AwsException("DeleteConflict",
                    "Cannot delete a policy attached to entities. Detach it first.", 409);
        }
        policies.delete(policyArn);
        LOG.infov("Deleted IAM policy: {0}", policyArn);
    }

    public List<IamPolicy> listPolicies(String scope, String pathPrefix) {
        if (scope != null && !scope.isBlank()
                && !"All".equalsIgnoreCase(scope)
                && !"AWS".equalsIgnoreCase(scope)
                && !"Local".equalsIgnoreCase(scope)) {
            throw new AwsException("ValidationError",
                    "Value '" + scope + "' at 'scope' failed to satisfy constraint: "
                            + "Member must satisfy enum value set: [All, AWS, Local]", 400);
        }
        String prefix = pathPrefix != null ? pathPrefix : "/";
        boolean blankScope = scope == null || scope.isBlank();
        boolean includeAws = blankScope || "All".equalsIgnoreCase(scope) || "AWS".equalsIgnoreCase(scope);
        boolean includeLocal = blankScope || "All".equalsIgnoreCase(scope) || "Local".equalsIgnoreCase(scope);

        List<IamPolicy> result = new ArrayList<>();
        if (includeLocal) {
            // Customer-managed policies live in the account-partitioned store. Exclude any
            // AWS-managed ARNs mirrored into the default account at seed time — those are
            // served from the global catalog below so the default account does not see them twice.
            policies.scan(k -> true).stream()
                    .filter(p -> !p.getArn().startsWith(AwsManagedPolicies.ARN_PREFIX))
                    .filter(p -> p.getPath().startsWith(prefix))
                    .forEach(result::add);
        }
        if (includeAws) {
            // AWS-managed policies are global (account-less arn:aws:iam::aws:policy/... ARN), so
            // every caller sees the full set regardless of the request account — mirroring the
            // getPolicy fix, and keeping the ListPolicies and GetPolicy read paths consistent.
            awsManagedPolicies.values().stream()
                    .filter(p -> p.getPath().startsWith(prefix))
                    .forEach(result::add);
        }
        return result;
    }

    public PolicyVersion createPolicyVersion(String policyArn, String document, boolean setAsDefault) {
        rejectIfAwsManaged(policyArn);
        IamPolicy policy = getPolicy(policyArn);
        Map<String, PolicyVersion> versions = policy.getVersions();
        PolicyVersion version;
        synchronized (versions) {
            int nextVersionNum = versions.size() + 1;
            if (nextVersionNum > 5) {
                throw new AwsException("LimitExceeded",
                        "A managed policy can have up to 5 versions.", 409);
            }
            String versionId = "v" + nextVersionNum;
            version = new PolicyVersion(versionId, document, setAsDefault);
            if (setAsDefault) {
                versions.values().forEach(v -> v.setDefaultVersion(false));
                policy.setDefaultVersionId(versionId);
            }
            versions.put(versionId, version);
        }
        policy.setUpdateDate(Instant.now());
        policies.put(policyArn, policy);
        return version;
    }

    public PolicyVersion getPolicyVersion(String policyArn, String versionId) {
        IamPolicy policy = getPolicy(policyArn);
        PolicyVersion version = policy.getVersions().get(versionId);
        if (version == null) {
            throw new AwsException("NoSuchEntity",
                    "Policy version " + versionId + " does not exist.", 404);
        }
        return version;
    }

    public void deletePolicyVersion(String policyArn, String versionId) {
        rejectIfAwsManaged(policyArn);
        IamPolicy policy = getPolicy(policyArn);
        if (versionId.equals(policy.getDefaultVersionId())) {
            throw new AwsException("DeleteConflict",
                    "Cannot delete the default version of a policy.", 409);
        }
        Map<String, PolicyVersion> versions = policy.getVersions();
        synchronized (versions) {
            if (!versions.containsKey(versionId)) {
                throw new AwsException("NoSuchEntity",
                        "Policy version " + versionId + " does not exist.", 404);
            }
            versions.remove(versionId);
        }
        policies.put(policyArn, policy);
    }

    public List<PolicyVersion> listPolicyVersions(String policyArn) {
        Map<String, PolicyVersion> versions = getPolicy(policyArn).getVersions();
        synchronized (versions) {
            return new ArrayList<>(versions.values());
        }
    }

    public void setDefaultPolicyVersion(String policyArn, String versionId) {
        rejectIfAwsManaged(policyArn);
        IamPolicy policy = getPolicy(policyArn);
        Map<String, PolicyVersion> versions = policy.getVersions();
        synchronized (versions) {
            if (!versions.containsKey(versionId)) {
                throw new AwsException("NoSuchEntity",
                        "Policy version " + versionId + " does not exist.", 404);
            }
            versions.values().forEach(v -> v.setDefaultVersion(false));
            versions.get(versionId).setDefaultVersion(true);
        }
        policy.setDefaultVersionId(versionId);
        policies.put(policyArn, policy);
    }

    public void tagPolicy(String policyArn, Map<String, String> newTags) {
        rejectIfAwsManaged(policyArn);
        IamPolicy policy = getPolicy(policyArn);
        policy.getTags().putAll(newTags);
        policies.put(policyArn, policy);
    }

    public void untagPolicy(String policyArn, List<String> tagKeys) {
        rejectIfAwsManaged(policyArn);
        IamPolicy policy = getPolicy(policyArn);
        tagKeys.forEach(policy.getTags()::remove);
        policies.put(policyArn, policy);
    }

    public Map<String, String> listPolicyTags(String policyArn) {
        return getPolicy(policyArn).getTags();
    }

    // =========================================================================
    // Policy Attachments — Users
    // =========================================================================

    public void attachUserPolicy(String userName, String policyArn) {
        IamUser user = getUser(userName);
        IamPolicy policy = getPolicy(policyArn);
        if (!user.getAttachedPolicyArns().contains(policyArn)) {
            user.getAttachedPolicyArns().add(policyArn);
            users.put(userName, user);
            policy.setAttachmentCount(policy.getAttachmentCount() + 1);
            policies.put(policyArn, policy);
        }
    }

    public void detachUserPolicy(String userName, String policyArn) {
        IamUser user = getUser(userName);
        if (!user.getAttachedPolicyArns().remove(policyArn)) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyArn + " is not attached to user " + userName + ".", 404);
        }
        users.put(userName, user);
        policies.get(policyArn).ifPresent(p -> {
            p.setAttachmentCount(Math.max(0, p.getAttachmentCount() - 1));
            policies.put(policyArn, p);
        });
    }

    public List<IamPolicy> listAttachedUserPolicies(String userName, String pathPrefix) {
        return getUser(userName).getAttachedPolicyArns().stream()
                .flatMap(arn -> resolvePolicy(arn).stream())
                .filter(p -> pathPrefix == null || p.getPath().startsWith(pathPrefix))
                .toList();
    }

    // =========================================================================
    // Policy Attachments — Groups
    // =========================================================================

    public void attachGroupPolicy(String groupName, String policyArn) {
        IamGroup group = getGroup(groupName);
        IamPolicy policy = getPolicy(policyArn);
        if (!group.getAttachedPolicyArns().contains(policyArn)) {
            group.getAttachedPolicyArns().add(policyArn);
            groups.put(groupName, group);
            policy.setAttachmentCount(policy.getAttachmentCount() + 1);
            policies.put(policyArn, policy);
        }
    }

    public void detachGroupPolicy(String groupName, String policyArn) {
        IamGroup group = getGroup(groupName);
        if (!group.getAttachedPolicyArns().remove(policyArn)) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyArn + " is not attached to group " + groupName + ".", 404);
        }
        groups.put(groupName, group);
        policies.get(policyArn).ifPresent(p -> {
            p.setAttachmentCount(Math.max(0, p.getAttachmentCount() - 1));
            policies.put(policyArn, p);
        });
    }

    public List<IamPolicy> listAttachedGroupPolicies(String groupName, String pathPrefix) {
        return getGroup(groupName).getAttachedPolicyArns().stream()
                .flatMap(arn -> resolvePolicy(arn).stream())
                .filter(p -> pathPrefix == null || p.getPath().startsWith(pathPrefix))
                .toList();
    }

    // =========================================================================
    // Policy Attachments — Roles
    // =========================================================================

    public void attachRolePolicy(String roleName, String policyArn) {
        IamRole role = getRole(roleName);
        IamPolicy policy = getPolicy(policyArn);
        if (!role.getAttachedPolicyArns().contains(policyArn)) {
            role.getAttachedPolicyArns().add(policyArn);
            roles.put(roleName, role);
            policy.setAttachmentCount(policy.getAttachmentCount() + 1);
            policies.put(policyArn, policy);
        }
    }

    public void detachRolePolicy(String roleName, String policyArn) {
        IamRole role = getRole(roleName);
        if (!role.getAttachedPolicyArns().remove(policyArn)) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyArn + " is not attached to role " + roleName + ".", 404);
        }
        roles.put(roleName, role);
        policies.get(policyArn).ifPresent(p -> {
            p.setAttachmentCount(Math.max(0, p.getAttachmentCount() - 1));
            policies.put(policyArn, p);
        });
    }

    public List<IamPolicy> listAttachedRolePolicies(String roleName, String pathPrefix) {
        return getRole(roleName).getAttachedPolicyArns().stream()
                .flatMap(arn -> resolvePolicy(arn).stream())
                .filter(p -> pathPrefix == null || p.getPath().startsWith(pathPrefix))
                .toList();
    }

    // =========================================================================
    // Inline Policies — Users
    // =========================================================================

    public void putUserPolicy(String userName, String policyName, String policyDocument) {
        IamUser user = getUser(userName);
        user.getInlinePolicies().put(policyName, policyDocument);
        users.put(userName, user);
    }

    public String getUserPolicy(String userName, String policyName) {
        IamUser user = getUser(userName);
        String doc = user.getInlinePolicies().get(policyName);
        if (doc == null) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyName + " not found for user " + userName + ".", 404);
        }
        return doc;
    }

    public void deleteUserPolicy(String userName, String policyName) {
        IamUser user = getUser(userName);
        if (user.getInlinePolicies().remove(policyName) == null) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyName + " not found for user " + userName + ".", 404);
        }
        users.put(userName, user);
    }

    public List<String> listUserPolicies(String userName) {
        return new ArrayList<>(getUser(userName).getInlinePolicies().keySet());
    }

    // =========================================================================
    // Inline Policies — Groups
    // =========================================================================

    public void putGroupPolicy(String groupName, String policyName, String policyDocument) {
        IamGroup group = getGroup(groupName);
        group.getInlinePolicies().put(policyName, policyDocument);
        groups.put(groupName, group);
    }

    public String getGroupPolicy(String groupName, String policyName) {
        IamGroup group = getGroup(groupName);
        String doc = group.getInlinePolicies().get(policyName);
        if (doc == null) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyName + " not found for group " + groupName + ".", 404);
        }
        return doc;
    }

    public void deleteGroupPolicy(String groupName, String policyName) {
        IamGroup group = getGroup(groupName);
        if (group.getInlinePolicies().remove(policyName) == null) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyName + " not found for group " + groupName + ".", 404);
        }
        groups.put(groupName, group);
    }

    public List<String> listGroupPolicies(String groupName) {
        return new ArrayList<>(getGroup(groupName).getInlinePolicies().keySet());
    }

    // =========================================================================
    // Inline Policies — Roles
    // =========================================================================

    public void putRolePolicy(String roleName, String policyName, String policyDocument) {
        IamRole role = getRole(roleName);
        Map<String, String> inlinePolicies = role.getInlinePolicies();
        synchronized (inlinePolicies) {
            long aggregateSize = inlinePolicies.entrySet().stream()
                    .filter(entry -> !entry.getKey().equals(policyName))
                    .mapToLong(entry -> nonWhitespaceLength(entry.getValue()))
                    .sum() + nonWhitespaceLength(policyDocument);
            if (aggregateSize > ROLE_INLINE_POLICY_SIZE_LIMIT) {
                throw new AwsException("LimitExceeded",
                        "Maximum policy size of 10240 bytes exceeded for role " + roleName, 409);
            }
            inlinePolicies.put(policyName, policyDocument);
            roles.put(roleName, role);
        }
    }

    private static int nonWhitespaceLength(String policyDocument) {
        int size = 0;
        for (int i = 0; i < policyDocument.length(); i++) {
            char character = policyDocument.charAt(i);
            if (character != ' ' && character != '\t' && character != '\n' && character != '\r') {
                size++;
            }
        }
        return size;
    }

    public String getRolePolicy(String roleName, String policyName) {
        IamRole role = getRole(roleName);
        String doc = role.getInlinePolicies().get(policyName);
        if (doc == null) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyName + " not found for role " + roleName + ".", 404);
        }
        return doc;
    }

    public void deleteRolePolicy(String roleName, String policyName) {
        IamRole role = getRole(roleName);
        if (role.getInlinePolicies().remove(policyName) == null) {
            throw new AwsException("NoSuchEntity",
                    "Policy " + policyName + " not found for role " + roleName + ".", 404);
        }
        roles.put(roleName, role);
    }

    public List<String> listRolePolicies(String roleName) {
        return new ArrayList<>(getRole(roleName).getInlinePolicies().keySet());
    }

    // =========================================================================
    // Access Keys
    // =========================================================================

    public AccessKey createAccessKey(String userName) {
        getUser(userName); // validates existence
        long existingCount = accessKeys.scan(k -> true).stream()
                .filter(ak -> userName.equals(ak.getUserName()))
                .count();
        if (existingCount >= 2) {
            throw new AwsException("LimitExceeded",
                    "Cannot exceed quota for AccessKeysPerUser: 2", 409);
        }
        String keyId = "AKIA" + randomId(16);
        String secretKey = randomSecret(40);
        AccessKey key = new AccessKey(keyId, secretKey, userName);
        accessKeys.put(keyId, key);
        LOG.infov("Created access key for user: {0}", userName);
        return key;
    }

    public void deleteAccessKey(String userName, String accessKeyId) {
        AccessKey key = accessKeys.get(accessKeyId)
                .orElseThrow(() -> new AwsException("NoSuchEntity",
                        "Access key " + accessKeyId + " not found.", 404));
        if (!key.getUserName().equals(userName)) {
            throw new AwsException("NoSuchEntity",
                    "Access key " + accessKeyId + " does not belong to user " + userName + ".", 404);
        }
        accessKeys.delete(accessKeyId);
    }

    public List<AccessKey> listAccessKeys(String userName) {
        getUser(userName); // validates existence
        return accessKeys.scan(k -> true).stream()
                .filter(ak -> userName.equals(ak.getUserName()))
                .toList();
    }

    public void updateAccessKey(String userName, String accessKeyId, String status) {
        AccessKey key = accessKeys.get(accessKeyId)
                .orElseThrow(() -> new AwsException("NoSuchEntity",
                        "Access key " + accessKeyId + " not found.", 404));
        if (!key.getUserName().equals(userName)) {
            throw new AwsException("NoSuchEntity",
                    "Access key " + accessKeyId + " does not belong to user " + userName + ".", 404);
        }
        if (!"Active".equals(status) && !"Inactive".equals(status)) {
            throw new AwsException("ValidationError",
                    "Status must be Active or Inactive.", 400);
        }
        key.setStatus(status);
        accessKeys.put(accessKeyId, key);
    }

    // =========================================================================
    // Instance Profiles
    // =========================================================================

    public InstanceProfile createInstanceProfile(String instanceProfileName, String path) {
        return createInstanceProfile(instanceProfileName, path, Map.of());
    }

    public InstanceProfile createInstanceProfile(String instanceProfileName, String path,
                                                 Map<String, String> tags) {
        if (instanceProfiles.get(instanceProfileName).isPresent()) {
            throw new AwsException("EntityAlreadyExists",
                    "Instance profile " + instanceProfileName + " already exists.", 409);
        }
        String profileId = "AIPA" + randomId(16);
        String normalizedPath = normalizePath(path);
        String arn = iamArn("instance-profile", normalizedPath, instanceProfileName);
        InstanceProfile profile = new InstanceProfile(profileId, instanceProfileName, normalizedPath, arn);
        if (tags != null) {
            profile.getTags().putAll(tags);
        }
        instanceProfiles.put(instanceProfileName, profile);
        LOG.infov("Created instance profile: {0}", instanceProfileName);
        return profile;
    }

    public InstanceProfile getInstanceProfile(String instanceProfileName) {
        return instanceProfiles.get(instanceProfileName)
                .orElseThrow(() -> new AwsException("NoSuchEntity",
                        "Instance profile " + instanceProfileName + " cannot be found.", 404));
    }

    public void deleteInstanceProfile(String instanceProfileName) {
        InstanceProfile profile = getInstanceProfile(instanceProfileName);
        if (!profile.getRoleNames().isEmpty()) {
            throw new AwsException("DeleteConflict",
                    "Cannot delete instance profile with associated roles.", 409);
        }
        instanceProfiles.delete(instanceProfileName);
    }

    public List<InstanceProfile> listInstanceProfiles(String pathPrefix) {
        String prefix = pathPrefix != null ? pathPrefix : "/";
        return instanceProfiles.scan(k -> true).stream()
                .filter(p -> p.getPath().startsWith(prefix))
                .toList();
    }

    public void tagInstanceProfile(String instanceProfileName, Map<String, String> newTags) {
        InstanceProfile profile = getInstanceProfile(instanceProfileName);
        profile.getTags().putAll(newTags);
        instanceProfiles.put(instanceProfileName, profile);
    }

    public void untagInstanceProfile(String instanceProfileName, List<String> tagKeys) {
        InstanceProfile profile = getInstanceProfile(instanceProfileName);
        tagKeys.forEach(profile.getTags()::remove);
        instanceProfiles.put(instanceProfileName, profile);
    }

    public Map<String, String> listInstanceProfileTags(String instanceProfileName) {
        return getInstanceProfile(instanceProfileName).getTags();
    }

    public void addRoleToInstanceProfile(String instanceProfileName, String roleName) {
        InstanceProfile profile = getInstanceProfile(instanceProfileName);
        getRole(roleName); // validates existence
        List<String> roleNames = profile.getRoleNames();
        synchronized (roleNames) {
            if (!roleNames.contains(roleName)) {
                if (!roleNames.isEmpty()) {
                    throw new AwsException("LimitExceeded",
                            "An instance profile can contain at most 1 role.", 409);
                }
                roleNames.add(roleName);
                instanceProfiles.put(instanceProfileName, profile);
            }
        }
    }

    public void removeRoleFromInstanceProfile(String instanceProfileName, String roleName) {
        InstanceProfile profile = getInstanceProfile(instanceProfileName);
        profile.getRoleNames().remove(roleName);
        instanceProfiles.put(instanceProfileName, profile);
    }

    public List<InstanceProfile> listInstanceProfilesForRole(String roleName) {
        getRole(roleName); // validates existence
        return instanceProfiles.scan(k -> true).stream()
                .filter(p -> p.getRoleNames().contains(roleName))
                .toList();
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    public Optional<String> findSecretKey(String accessKeyId) {
        Optional<String> fromAccessKey = accessKeys.get(accessKeyId)
                .filter(key -> "Active".equals(key.getStatus()))
                .map(AccessKey::getSecretAccessKey);
        if (fromAccessKey.isPresent()) {
            return fromAccessKey;
        }
        return findUnexpiredSession(accessKeyId).map(SessionCredential::getSecretAccessKey);
    }

    /**
     * Resolves the signing secret used by presigned data-plane authentication.
     * Temporary credentials are usable only when their session token is present,
     * matches the stored credential, and has not expired. Long-term credentials
     * must resolve to a persisted IAM access key.
     */
    public Optional<String> findSigningSecret(String accessKeyId, String sessionToken) {
        if (isTemporaryAccessKey(accessKeyId)) {
            return findActiveSession(accessKeyId, sessionToken)
                    .map(SessionCredential::getSecretAccessKey);
        }
        return findSecretKey(accessKeyId);
    }

    public Optional<String> findSessionToken(String accessKeyId) {
        return findUnexpiredSession(accessKeyId).map(SessionCredential::getSessionToken);
    }

    public Optional<AccessKey> findAccessKey(String accessKeyId) {
        return accessKeys.get(accessKeyId);
    }

    public Optional<IamUser> findUser(String userName) {
        return users.get(userName);
    }

    // =========================================================================
    // IAM Enforcement — session tracking and policy collection
    // =========================================================================

    /**
     * Stores an assumed-role session so the enforcement filter can resolve its policies.
     */
    public void registerSession(String sessionAccessKeyId, String roleArn, java.time.Instant expiration) {
        sessions.put(sessionAccessKeyId, new SessionCredential(sessionAccessKeyId, roleArn, expiration));
    }

    /**
     * Stores an assumed-role session with an optional inline session policy document.
     */
    public void registerSession(String sessionAccessKeyId, String roleArn, java.time.Instant expiration,
                                String sessionPolicyDocument) {
        sessions.put(sessionAccessKeyId,
                new SessionCredential(sessionAccessKeyId, roleArn, expiration, sessionPolicyDocument));
    }

    /**
     * Stores an assumed-role session including the temporary secret access key so that
     * {@link #findSecretKey(String)} can resolve it for RDS/ElastiCache IAM token validation.
     */
    public void registerSession(String sessionAccessKeyId, String secretAccessKey, String roleArn,
                                java.time.Instant expiration, String sessionPolicyDocument) {
        sessions.put(sessionAccessKeyId,
                new SessionCredential(sessionAccessKeyId, secretAccessKey, roleArn, expiration, sessionPolicyDocument));
    }

    /**
     * Stores an assumed-role session and records {@code originAccountId} — the account of the
     * caller that minted it. The origin lets {@link #resolveAccountId(String, String)} route temporary
     * credentials that carry no role ARN (e.g. GetSessionToken) back to the caller's account.
     */
    public void registerSession(String sessionAccessKeyId, String secretAccessKey, String roleArn,
                                java.time.Instant expiration, String sessionPolicyDocument,
                                String originAccountId) {
        registerSession(sessionAccessKeyId, secretAccessKey, null, roleArn, null, null, null,
                expiration, sessionPolicyDocument, originAccountId, null, null);
    }

    public void registerSession(String sessionAccessKeyId, String secretAccessKey, String sessionToken,
                                String roleArn, String roleSessionName, String targetAccountId,
                                String assumedRolePrincipalId, java.time.Instant expiration,
                                String sessionPolicyDocument, String originAccountId) {
        registerSession(sessionAccessKeyId, secretAccessKey, sessionToken, roleArn, roleSessionName,
                targetAccountId, assumedRolePrincipalId, expiration, sessionPolicyDocument,
                originAccountId, null, null);
    }

    public void registerSession(String sessionAccessKeyId, String secretAccessKey, String sessionToken,
                                String roleArn, String roleSessionName, String targetAccountId,
                                String assumedRolePrincipalId, java.time.Instant expiration,
                                String sessionPolicyDocument, String originAccountId,
                                String sourcePrincipalArn, String sourcePrincipalId) {
        registerSession(sessionAccessKeyId, secretAccessKey, sessionToken, roleArn, roleSessionName,
                targetAccountId, assumedRolePrincipalId, expiration, sessionPolicyDocument,
                originAccountId, sourcePrincipalArn, sourcePrincipalId, null, false, false);
    }

    public void registerSession(String sessionAccessKeyId, String secretAccessKey, String sessionToken,
                                String roleArn, String roleSessionName, String targetAccountId,
                                String assumedRolePrincipalId, java.time.Instant expiration,
                                String sessionPolicyDocument, String originAccountId,
                                String sourcePrincipalArn, String sourcePrincipalId,
                                SessionType sessionType, boolean mfaAuthenticated,
                                boolean principalBindingRequired) {
        sessions.put(sessionAccessKeyId, new SessionCredential(
                sessionAccessKeyId, secretAccessKey, sessionToken, roleArn, roleSessionName,
                targetAccountId, assumedRolePrincipalId, expiration, sessionPolicyDocument,
                originAccountId, sourcePrincipalArn, sourcePrincipalId, sessionType,
                mfaAuthenticated, principalBindingRequired));
    }

    /**
     * Resolves the account a temporary access key belongs to: the account encoded in the
     * session's role (or federated-user) ARN when present, otherwise the caller account captured
     * at mint time. Returns empty for unknown or expired sessions so callers fall back to the
     * default account.
     */
    @Override
    public Optional<String> resolveAccountId(String accessKeyId, String sessionToken) {
        return Optional.of(requireActiveSession(accessKeyId, sessionToken))
                .flatMap(this::resolveTargetAccountId);
    }

    /**
     * Looks up a session by its temporary access key ID independent of the request's account.
     *
     * <p>Sessions are keyed by a globally-unique access key (e.g. {@code ASIA...}) but stored in
     * the minting account's namespace. Account routing must resolve the session <em>before</em> the
     * request's account is known, so a normal account-scoped {@code get} would miss it. This scans
     * across all accounts; the access key's global uniqueness keeps the result unambiguous.
     */
    private Optional<SessionCredential> findSessionAnyAccount(String accessKeyId) {
        if (!isTemporaryAccessKey(accessKeyId)) {
            return Optional.empty();
        }
        if (sessions instanceof AccountAwareStorageBackend<SessionCredential> aware) {
            return Optional.ofNullable(aware.scanAllAccountsAsMap().get(accessKeyId));
        }
        return sessions.get(accessKeyId);
    }

    private Optional<SessionCredential> findUnexpiredSession(String accessKeyId) {
        Optional<SessionCredential> session = findSessionAnyAccount(accessKeyId);
        if (session.isPresent() && isExpired(session.get())) {
            deleteSession(accessKeyId, session.get());
            return Optional.empty();
        }
        return session;
    }

    Optional<SessionCredential> findActiveSession(String accessKeyId, String sessionToken) {
        try {
            return Optional.of(requireActiveSession(accessKeyId, sessionToken));
        } catch (AwsException e) {
            return Optional.empty();
        }
    }

    SessionCredential requireActiveSession(String accessKeyId, String sessionToken) {
        if (!isTemporaryAccessKey(accessKeyId)) {
            throw invalidSessionToken();
        }
        Optional<SessionCredential> session = findSessionAnyAccount(accessKeyId);
        if (session.isEmpty()) {
            throw invalidSessionToken();
        }
        if (isExpired(session.get())) {
            deleteSession(accessKeyId, session.get());
            throw new AwsException("ExpiredToken",
                    "The security token included in the request is expired", 403);
        }
        if (sessionToken == null || sessionToken.isBlank()
                || session.get().getSessionToken() == null
                || !session.get().getSessionToken().equals(sessionToken)) {
            throw invalidSessionToken();
        }
        validatePrincipalBinding(session.get());
        return session.get();
    }

    /**
     * Applies restrictions intrinsic to credentials issued by {@code GetSessionToken}.
     * These restrictions are evaluated in addition to the issuing principal's policies.
     */
    public boolean isSessionActionAllowed(String accessKeyId, String sessionToken, String action) {
        if (!isTemporaryAccessKey(accessKeyId)) {
            return true;
        }
        SessionCredential session = requireActiveSession(accessKeyId, sessionToken);
        if (session.getSessionType() != SessionType.GET_SESSION_TOKEN) {
            return true;
        }
        if (action.startsWith("iam:")) {
            return false;
        }
        if (action.startsWith("sts:")) {
            return "sts:AssumeRole".equals(action) || "sts:GetCallerIdentity".equals(action);
        }
        return true;
    }

    public SessionIdentity resolveSessionIdentity(String accessKeyId, String sessionToken) {
        SessionCredential session = requireActiveSession(accessKeyId, sessionToken);
        String accountId = resolveTargetAccountId(session)
                .orElseThrow(IamService::invalidSessionToken);
        String roleArn = session.getRoleArn();
        if (roleArn == null || roleArn.isBlank()) {
            String principalArn = session.getSourcePrincipalArn();
            String principalId = session.getSourcePrincipalId();
            return new SessionIdentity(accountId,
                    principalArn == null || principalArn.isBlank()
                            ? AwsArnUtils.Arn.of("iam", "", accountId, "root").toString()
                            : principalArn,
                    principalId == null || principalId.isBlank() ? accountId : principalId);
        }
        if (roleArn.contains(":federated-user/")) {
            String principalId = session.getAssumedRolePrincipalId();
            return new SessionIdentity(accountId, roleArn,
                    principalId == null || principalId.isBlank() ? accountId : principalId);
        }

        String roleName = roleArn.contains("/")
                ? roleArn.substring(roleArn.lastIndexOf('/') + 1) : "UnknownRole";
        String sessionName = session.getRoleSessionName();
        if (sessionName == null || sessionName.isBlank()) {
            // Sessions persisted before roleSessionName was added used this stable suffix.
            sessionName = "floci-session";
        }
        String principalId = session.getAssumedRolePrincipalId();
        if (principalId == null || principalId.isBlank()) {
            // Legacy persisted sessions have no principal id. Derive a stable AROA-shaped value
            // from the role ARN so restart behavior remains deterministic without rewriting data.
            principalId = legacyRolePrincipalId(roleArn);
        }
        String arn = AwsArnUtils.Arn.of("sts", "", accountId,
                "assumed-role/" + roleName + "/" + sessionName).toString();
        return new SessionIdentity(accountId, arn, principalId + ":" + sessionName);
    }

    public record SessionIdentity(String accountId, String arn, String userId) {}

    private Optional<String> resolveTargetAccountId(SessionCredential session) {
        String account = session.getTargetAccountId();
        if (account == null || account.isBlank()) {
            account = AwsArnUtils.accountOrDefault(session.getRoleArn(), session.getOriginAccountId());
        }
        return account == null || account.isBlank() ? Optional.empty() : Optional.of(account);
    }

    private static boolean isExpired(SessionCredential session) {
        return session.getExpiration() != null && !session.getExpiration().isAfter(Instant.now());
    }

    private static AwsException invalidSessionToken() {
        return new AwsException("InvalidClientTokenId",
                "The security token included in the request is invalid", 403);
    }

    private void validatePrincipalBinding(SessionCredential session) {
        boolean issuedRoleSession = session.getSessionType() == SessionType.ASSUME_ROLE
                || session.getSessionType() == SessionType.WEB_IDENTITY
                || session.getSessionType() == SessionType.SAML;
        if (!session.isPrincipalBindingRequired() && !issuedRoleSession) {
            return;
        }
        if (session.getSessionType() == SessionType.GET_SESSION_TOKEN) {
            validateSourcePrincipalBinding(session);
            return;
        }
        String roleArn = session.getRoleArn();
        String principalId = session.getAssumedRolePrincipalId();
        if (roleArn == null || roleArn.isBlank() || principalId == null || principalId.isBlank()
                || roleArn.contains(":federated-user/")) {
            throw invalidSessionToken();
        }
        String accountId = AwsArnUtils.accountOrDefault(roleArn, session.getTargetAccountId());
        String roleName = roleArn.substring(roleArn.lastIndexOf('/') + 1);
        IamRole role = findRole(accountId, roleName).orElseThrow(IamService::invalidSessionToken);
        if (!Objects.equals(principalId, role.getRoleId())) {
            throw invalidSessionToken();
        }
    }

    private void validateSourcePrincipalBinding(SessionCredential session) {
        String principalArn = session.getSourcePrincipalArn();
        String principalId = session.getSourcePrincipalId();
        if (principalArn == null || principalArn.isBlank() || principalId == null || principalId.isBlank()) {
            throw invalidSessionToken();
        }
        if (principalArn.endsWith(":root")) {
            String accountId = AwsArnUtils.accountOrDefault(principalArn, session.getOriginAccountId());
            if (!Objects.equals(accountId, principalId)) {
                throw invalidSessionToken();
            }
            return;
        }
        if (!principalArn.contains(":user/")) {
            throw invalidSessionToken();
        }
        String accountId = AwsArnUtils.accountOrDefault(principalArn, session.getOriginAccountId());
        String userName = principalArn.substring(principalArn.lastIndexOf('/') + 1);
        IamUser user = findUser(accountId, userName).orElseThrow(IamService::invalidSessionToken);
        if (!Objects.equals(principalId, user.getUserId())) {
            throw invalidSessionToken();
        }
    }

    private Optional<IamUser> findUser(String accountId, String userName) {
        if (users instanceof AccountAwareStorageBackend<IamUser> aware) {
            return aware.getForAccount(accountId, userName);
        }
        return users.get(userName);
    }

    private static String legacyRolePrincipalId(String roleArn) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(roleArn.getBytes(StandardCharsets.UTF_8));
            StringBuilder value = new StringBuilder("AROA");
            for (int i = 0; i < 8; i++) {
                value.append(String.format("%02X", hash[i]));
            }
            return value.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /**
     * Resolves the full caller context for the given access key, including identity policies,
     * optional session policy, and optional permission boundary.
     *
     * <p>Returns {@code null} if the access key is unknown (bypass — backward-compatible).
     */
    public CallerContext resolveCallerContext(String accessKeyId) {
        // Check user access keys
        Optional<AccessKey> akOpt = accessKeys.get(accessKeyId)
                .filter(key -> "Active".equals(key.getStatus()));
        if (akOpt.isPresent()) {
            String userName = akOpt.get().getUserName();
            List<String> identityPolicies = collectUserPolicies(userName);
            String boundaryDoc = resolveUserBoundaryDocument(userName);
            return new CallerContext(identityPolicies, null, boundaryDoc);
        }

        // Check assumed-role sessions. These can be stored under the account that minted the
        // session, while request routing for temporary credentials uses the role's account.
        Optional<SessionCredential> sessionOpt = findSessionForCallerContext(accessKeyId);
        if (sessionOpt.isPresent()) {
            SessionCredential session = sessionOpt.get();
            if (session.getExpiration() != null && session.getExpiration().isBefore(java.time.Instant.now())) {
                deleteSession(accessKeyId, session);
                return null; // expired — unknown key → bypass
            }
            validatePrincipalBinding(session);

            if (session.getRoleArn() == null) {
                return resolveSourcePrincipalContext(session.getSourcePrincipalArn());
            }
            List<String> identityPolicies = collectRolePolicies(session.getRoleArn());
            String boundaryDoc = resolveRoleBoundaryDocument(session.getRoleArn());
            return new CallerContext(identityPolicies, session.getSessionPolicyDocument(), boundaryDoc);
        }

        // Unknown key — bypass
        return null;
    }

    public CallerContext resolveCallerContext(String accessKeyId, String sessionToken) {
        if (!isTemporaryAccessKey(accessKeyId)) {
            return resolveCallerContext(accessKeyId);
        }
        SessionCredential session = requireActiveSession(accessKeyId, sessionToken);
        if (session.getRoleArn() == null) {
            return resolveSourcePrincipalContext(session.getSourcePrincipalArn());
        }
        List<String> identityPolicies = collectRolePolicies(session.getRoleArn());
        String boundaryDoc = resolveRoleBoundaryDocument(session.getRoleArn());
        return new CallerContext(identityPolicies, session.getSessionPolicyDocument(), boundaryDoc);
    }

    private CallerContext resolveSourcePrincipalContext(String sourcePrincipalArn) {
        if (sourcePrincipalArn == null || sourcePrincipalArn.isBlank()
                || sourcePrincipalArn.endsWith(":root")) {
            return null;
        }
        return resolvePrincipalContext(sourcePrincipalArn);
    }

    private Optional<SessionCredential> findSessionForCallerContext(String accessKeyId) {
        if (accessKeyId == null || accessKeyId.isBlank()) {
            return Optional.empty();
        }
        Optional<SessionCredential> session = sessions.get(accessKeyId);
        if (session.isPresent()) {
            return session;
        }
        if (!isTemporaryAccessKey(accessKeyId)) {
            return Optional.empty();
        }
        return findSessionAnyAccount(accessKeyId);
    }

    /**
     * Collects all identity-based policy documents applicable to the caller identified
     * by {@code accessKeyId}.
     *
     * <p>Returns {@code null} if the access key is unknown (bypass — backward-compatible).
     * Returns an empty list if the key is known but has no policies attached (implicit deny).
     *
     * <p>Order: inline policies first, then attached managed policies.
     */
    public List<String> resolveCallerPolicies(String accessKeyId) {
        CallerContext ctx = resolveCallerContext(accessKeyId);
        return ctx == null ? null : ctx.identityPolicies();
    }

    public Optional<String> resolveCallerArn(String accessKeyId) {
        if (accessKeyId == null || accessKeyId.isBlank()) {
            return Optional.empty();
        }

        Optional<AccessKey> akOpt = accessKeys.get(accessKeyId);
        if (akOpt.isPresent()) {
            String userName = akOpt.get().getUserName();
            return users.get(userName).map(IamUser::getArn);
        }

        Optional<SessionCredential> sessionOpt = findSessionForCallerContext(accessKeyId);
        if (sessionOpt.isPresent()) {
            SessionCredential session = sessionOpt.get();
            if (session.getExpiration() != null && session.getExpiration().isBefore(java.time.Instant.now())) {
                deleteSession(accessKeyId, session);
                return Optional.empty();
            }
            String roleArn = session.getRoleArn();
            String roleName = roleArn.contains("/") ? roleArn.substring(roleArn.lastIndexOf('/') + 1) : "UnknownRole";
            String accountId = AwsArnUtils.accountOrDefault(roleArn, regionResolver.getAccountId());
            return Optional.of(AwsArnUtils.Arn.of("sts", "", accountId, "assumed-role/" + roleName + "/floci-session").toString());
        }

        return Optional.empty();
    }

    public Optional<String> resolveCallerArn(String accessKeyId, String sessionToken) {
        if (isTemporaryAccessKey(accessKeyId)) {
            return Optional.of(resolveSessionIdentity(accessKeyId, sessionToken).arn());
        }
        return resolveCallerArn(accessKeyId);
    }

    public Optional<String> resolveCallerPrincipalId(String accessKeyId) {
        if (accessKeyId == null || accessKeyId.isBlank()) {
            return Optional.empty();
        }
        Optional<AccessKey> accessKey = accessKeys.get(accessKeyId);
        if (accessKey.isPresent()) {
            return users.get(accessKey.get().getUserName()).map(IamUser::getUserId);
        }
        return Optional.empty();
    }

    static boolean isTemporaryAccessKey(String accessKeyId) {
        return accessKeyId != null && accessKeyId.startsWith(TEMPORARY_ACCESS_KEY_PREFIX);
    }

    private void deleteSession(String accessKeyId, SessionCredential session) {
        String originAccountId = session.getOriginAccountId();
        if (originAccountId != null && !originAccountId.isBlank()
                && sessions instanceof AccountAwareStorageBackend<SessionCredential> aware) {
            aware.deleteForAccount(originAccountId, accessKeyId);
            return;
        }
        sessions.delete(accessKeyId);
    }

    /** Removes a temporary credential when its provider-owned lifecycle ends. */
    public void unregisterSession(String accessKeyId) {
        findSessionAnyAccount(accessKeyId)
                .ifPresent(session -> deleteSession(accessKeyId, session));
    }

    public CallerContext resolvePrincipalContext(String principalArn) {
        if (principalArn == null || principalArn.isBlank()) {
            throw new AwsException("ValidationError", "PolicySourceArn is required.", 400);
        }
        if (principalArn.contains(":user/")) {
            String userName = principalArn.substring(principalArn.lastIndexOf('/') + 1);
            List<String> identityPolicies = collectUserPolicies(userName);
            if (identityPolicies == null) {
                throw new AwsException("NoSuchEntity", "User " + userName + " cannot be found.", 404);
            }
            return new CallerContext(identityPolicies, null, resolveUserBoundaryDocument(userName));
        }
        if (principalArn.contains(":role/")) {
            String roleName = principalArn.substring(principalArn.lastIndexOf('/') + 1);
            List<String> identityPolicies = collectRolePolicies(principalArn);
            if (identityPolicies == null) {
                throw new AwsException("NoSuchEntity", "Role " + roleName + " cannot be found.", 404);
            }
            return new CallerContext(identityPolicies, null, resolveRoleBoundaryDocument(principalArn));
        }
        throw new AwsException("InvalidInput", "PolicySourceArn must identify an IAM user or role.", 400);
    }

    private String resolveUserBoundaryDocument(String userName) {
        return users.get(userName)
                .map(IamUser::getPermissionsBoundaryArn)
                .flatMap(this::resolvePolicy)
                .map(IamPolicy::getDefaultDocument)
                .orElse(null);
    }

    private String resolveRoleBoundaryDocument(String roleArn) {
        if (roleArn == null) {
            return null;
        }
        String roleName = roleArn.contains("/") ? roleArn.substring(roleArn.lastIndexOf('/') + 1) : roleArn;
        return roles.get(roleName)
                .map(IamRole::getPermissionsBoundaryArn)
                .flatMap(this::resolvePolicy)
                .map(IamPolicy::getDefaultDocument)
                .orElse(null);
    }

    // =========================================================================
    // Permission Boundaries
    // =========================================================================

    public void putUserPermissionsBoundary(String userName, String permissionsBoundaryArn) {
        getPolicy(permissionsBoundaryArn); // validate policy exists
        IamUser user = getUser(userName);
        user.setPermissionsBoundaryArn(permissionsBoundaryArn);
        users.put(userName, user);
        LOG.infov("Set permissions boundary for user {0}: {1}", userName, permissionsBoundaryArn);
    }

    public void deleteUserPermissionsBoundary(String userName) {
        IamUser user = getUser(userName);
        if (user.getPermissionsBoundaryArn() == null) {
            throw new AwsException("NoSuchEntity",
                    "User " + userName + " does not have a permissions boundary.", 404);
        }
        user.setPermissionsBoundaryArn(null);
        users.put(userName, user);
        LOG.infov("Deleted permissions boundary for user: {0}", userName);
    }

    public void putRolePermissionsBoundary(String roleName, String permissionsBoundaryArn) {
        getPolicy(permissionsBoundaryArn); // validate policy exists
        IamRole role = getRole(roleName);
        role.setPermissionsBoundaryArn(permissionsBoundaryArn);
        roles.put(roleName, role);
        LOG.infov("Set permissions boundary for role {0}: {1}", roleName, permissionsBoundaryArn);
    }

    public void deleteRolePermissionsBoundary(String roleName) {
        IamRole role = getRole(roleName);
        if (role.getPermissionsBoundaryArn() == null) {
            throw new AwsException("NoSuchEntity",
                    "Role " + roleName + " does not have a permissions boundary.", 404);
        }
        role.setPermissionsBoundaryArn(null);
        roles.put(roleName, role);
        LOG.infov("Deleted permissions boundary for role: {0}", roleName);
    }

    private List<String> collectUserPolicies(String userName) {
        Optional<IamUser> userOpt = users.get(userName);
        if (userOpt.isEmpty()) {
            return null;
        }
        IamUser user = userOpt.get();

        // User inline policies
        List<String> docs = new ArrayList<>(user.getInlinePolicies().values());

        // User attached managed policies
        for (String arn : user.getAttachedPolicyArns()) {
            Optional<IamPolicy> p = resolvePolicy(arn);
            if (p.isPresent() && p.get().getDefaultDocument() != null) {
                docs.add(p.get().getDefaultDocument());
            }
        }

        // Group policies
        for (String groupName : user.getGroupNames()) {
            Optional<IamGroup> groupOpt = groups.get(groupName);
            if (groupOpt.isEmpty()) continue;
            IamGroup group = groupOpt.get();
            docs.addAll(group.getInlinePolicies().values());
            for (String arn : group.getAttachedPolicyArns()) {
                Optional<IamPolicy> p = resolvePolicy(arn);
                if (p.isPresent() && p.get().getDefaultDocument() != null) {
                    docs.add(p.get().getDefaultDocument());
                }
            }
        }

        return docs;
    }

    private List<String> collectRolePolicies(String roleArn) {
        if (roleArn == null) {
            return null;
        }
        String roleName = roleArn.contains("/") ? roleArn.substring(roleArn.lastIndexOf('/') + 1) : roleArn;
        Optional<IamRole> roleOpt = roles.get(roleName);
        if (roleOpt.isEmpty()) {
            return null;
        }
        IamRole role = roleOpt.get();
        List<String> docs = new ArrayList<>();

        // Role inline policies
        docs.addAll(role.getInlinePolicies().values());

        // Role attached managed policies
        for (String arn : role.getAttachedPolicyArns()) {
            Optional<IamPolicy> p = resolvePolicy(arn);
            if (p.isPresent() && p.get().getDefaultDocument() != null) {
                docs.add(p.get().getDefaultDocument());
            }
        }

        return docs;
    }

    private String iamArn(String resourceType, String path, String name) {
        return AwsArnUtils.Arn.of("iam", "", regionResolver.getAccountId(), resourceType + path + name).toString();
    }

    private static String normalizePath(String path) {
        if (path == null || path.isEmpty()) return "/";
        String p = path;
        if (!p.startsWith("/")) p = "/" + p;
        if (!p.endsWith("/")) p = p + "/";
        return p;
    }

    private static String randomId(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARS.charAt(ThreadLocalRandom.current().nextInt(CHARS.length())));
        }
        return sb.toString();
    }

    private static String randomSecret(int length) {
        String secretChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(secretChars.charAt(ThreadLocalRandom.current().nextInt(secretChars.length())));
        }
        return sb.toString();
    }
}
