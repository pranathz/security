/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.dlic.rest.api;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.io.IOException;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.OpenSearchSecurityException;

import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.EndpointValidator;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.dlic.rest.validation.ValidationResult;

import org.opensearch.security.privileges.ActionPrivileges;
import org.opensearch.security.privileges.PrivilegesEvaluationContext;
import org.opensearch.security.privileges.PrivilegesEvaluatorResponse;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.resolver.IndexResolverReplacer;
import org.opensearch.security.securityconf.FlattenedActionGroups;

import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import com.google.common.collect.ImmutableSet;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.forbiddenMessage;
import static org.opensearch.security.dlic.rest.api.Responses.internalServerError;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class ImpactAnalysisApiAction extends AbstractApiAction {

    private static final String ROLES = "roles";
    private static final String ROLES_MAPPING = "roles_mapping";
    private static final String CONFIG = "config";
    private static final String ACTION_GROUPS = "action_groups";
    private static final String ACTION = "action";

    private final IndexResolverReplacer irr;
    private final IndexNameExpressionResolver indexNameExpressionResolver;


    private static final List<Route> routes = addRoutesPrefix(List.of(new Route(RestRequest.Method.POST, "/impact_analysis")));
    public ImpactAnalysisApiAction(ClusterService clusterService, ThreadPool threadPool, SecurityApiDependencies securityApiDependencies, IndexResolverReplacer irr,
                                   IndexNameExpressionResolver indexNameExpressionResolver) {
        super(Endpoint.IMPACT_ANALYSIS, clusterService, threadPool, securityApiDependencies);
        this.irr = irr;
        this.indexNameExpressionResolver = indexNameExpressionResolver;
        this.requestHandlersBuilder.add(RestRequest.Method.POST, this::handleImpactAnalysisRequest).withAccessHandler(request -> true);
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }

    private void handleImpactAnalysisRequest(RestChannel channel, RestRequest request, Client client) {
        try {

            Map<String, Object> proposedBody = DefaultObjectMapper.objectMapper.readValue(
                request.content().utf8ToString(),
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {
                }
            );

            @SuppressWarnings("unchecked")
            Map<String, Object> proposedRoles = (Map<String, Object>) proposedBody.getOrDefault(ROLES, Map.of());
            @SuppressWarnings("unchecked")
            Map<String, Object> proposedRoleMappings = (Map<String, Object>) proposedBody.getOrDefault(ROLES_MAPPING, Map.of());
            @SuppressWarnings("unchecked")
            Map<String, Object> proposedSecurityConfig = (Map<String, Object>) proposedBody.getOrDefault(CONFIG, Map.of());
            @SuppressWarnings("unchecked")
            Map<String, Object> proposedActionGroups = (Map<String, Object>) proposedBody.getOrDefault(ACTION_GROUPS, Map.of());

            ActionPrivileges actionPrivileges=buildActionPrivileges(
                    proposedRoles,
                    proposedActionGroups,
                    securityApiDependencies.settings()
            );

            PrivilegesEvaluationContext context = buildPrivilegesEvaluationContext(
                    proposedBody,
                    threadPool,
                    clusterService,
                    irr,
                    indexNameExpressionResolver,
                    actionPrivileges
            );

            PrivilegesEvaluatorResponse response = securityApiDependencies.privilegesEvaluator().evaluate(context);
            // Load current configuration
            SecurityDynamicConfiguration<?> currentRoles = load(CType.ROLES, false);
            SecurityDynamicConfiguration<?> currentRoleMappings = load(CType.ROLESMAPPING, false);
            SecurityDynamicConfiguration<?> currentSecurityConfig = load(CType.CONFIG, false);
            SecurityDynamicConfiguration<?> currentActionGroups = load(CType.ACTIONGROUPS, false);

            Map<String, Object> currentRoleMappingsMap = new HashMap<>();
            currentRoleMappings.getCEntries()
                .forEach(
                    (k, v) -> currentRoleMappingsMap.put(String.valueOf(k), DefaultObjectMapper.objectMapper.convertValue(v, Map.class))
                );

            Map<String, Object> currentRolesMap = new HashMap<>();
            currentRoles.getCEntries()
                .forEach((k, v) -> currentRolesMap.put(String.valueOf(k), DefaultObjectMapper.objectMapper.convertValue(v, Map.class)));

            Map<String, Object> currentSecurityConfigMap = new HashMap<>();
            currentSecurityConfig.getCEntries()
                    .forEach((k, v) -> currentSecurityConfigMap.put(String.valueOf(k), DefaultObjectMapper.objectMapper.convertValue(v, Map.class)));

            Map<String, Object> currentActionGroupsMap = new HashMap<>();
            currentActionGroups.getCEntries()
                    .forEach((k, v) -> currentActionGroupsMap.put(String.valueOf(k), DefaultObjectMapper.objectMapper.convertValue(v, Map.class)));


            Map<String, Object> impactAnalysis = analyzeImpact(
                    currentRolesMap,
                    currentRoleMappingsMap,
                    currentSecurityConfigMap,
                    currentActionGroupsMap,
                    proposedRoles,
                    proposedRoleMappings,
                    proposedSecurityConfig,
                    proposedActionGroups
            );

            // Build response
            XContentBuilder builder = channel.newBuilder();
            builder.startObject();
            builder.field("accessAllowed", response.isAllowed());
            builder.field("missingPrivileges", response.getMissingPrivileges());
            builder.field("impactAnalysis", impactAnalysis);
            builder.endObject();

            channel.sendResponse(new BytesRestResponse(RestStatus.OK, builder));

        } catch (Exception e) {
            internalServerError(channel, "Error analyzing impact: " + e.getMessage());
        }
    }
    private ActionPrivileges buildActionPrivileges(
            Map<String, Object> proposedRoles,
            Map<String, Object> proposedActionGroups,
            Settings settings
    ) throws IOException {

        SecurityDynamicConfiguration<RoleV7> rolesConfig = SecurityDynamicConfiguration.fromMap(proposedRoles, CType.ROLES);
        SecurityDynamicConfiguration<ActionGroupsV7> actionGroupsConfig = SecurityDynamicConfiguration.fromMap(proposedActionGroups, CType.ACTIONGROUPS);
        FlattenedActionGroups flattenedActionGroups = new FlattenedActionGroups(actionGroupsConfig.withStaticConfig());
        return new RoleBasedActionPrivileges(
                rolesConfig.withStaticConfig(),
                flattenedActionGroups,
                settings
        );
    }

    @SuppressWarnings("unchecked")
    private PrivilegesEvaluationContext buildPrivilegesEvaluationContext(
            Map<String, Object> proposedBody,
            ThreadPool threadPool,
            ClusterService clusterService,
            IndexResolverReplacer irr,
            IndexNameExpressionResolver indexNameExpressionResolver,
            ActionPrivileges actionPrivileges
    ) {
        ThreadContext threadContext = threadPool.getThreadContext();
        String action = (String) proposedBody.get(ACTION);
        if (action == null || action.isEmpty()) {
            throw new IllegalArgumentException("Missing action in request body");
        }
        String index = proposedBody.containsKey("index") ? (String) proposedBody.get("index") : null;

        User user = getAuthenticatedUser(threadContext);

        Map<String, Object> proposedRoleMappings = (Map<String, Object>) proposedBody.get(ROLES_MAPPING);
        ImmutableSet<String> mappedRoles = getMappedRolesForUser(user,proposedRoleMappings);

        Supplier<ClusterState> clusterStateSupplier = clusterService::state;
        ActionRequest actionRequest = buildActionRequest(action, index);

        return new PrivilegesEvaluationContext(
                user,
                mappedRoles,
                action,
                actionRequest,
                null,
                irr,
                indexNameExpressionResolver,
                clusterStateSupplier,
                actionPrivileges
        );
    }

    @SuppressWarnings("unchecked")
    private ImmutableSet<String> getMappedRolesForUser(User user, Map<String, Object> proposedRoleMappings) {
        Set<String> mappedRoles = new HashSet<>();

        for (Map.Entry<String, Object> rps : proposedRoleMappings.entrySet()) {
            String roleName = rps.getKey();
            Map<String, Object> roleMapping = (Map<String, Object>) rps.getValue();

            List<String> users = (List<String>) roleMapping.getOrDefault("users", List.of());
            if (users.contains(user.getName())) {
                mappedRoles.add(roleName);
            }
        }

        return ImmutableSet.copyOf(mappedRoles);
    }

    private ActionRequest buildActionRequest(String action, String index) {
        switch (action)  {
            case "indices:data/read/search":
                return new SearchRequest(index);

            case "indices:data/read/get":
                return new GetRequest(index);

            case "indices:data/write/delete":
                return new DeleteRequest(index);

            case "indices:data/write/index":
                return new IndexRequest(index)
                        .source("{\"field\":\"value\"}", XContentType.JSON);

            default:
                return new ActionRequest() {
                    @Override
                    public ActionRequestValidationException validate() {
                        return null;
                    }
                };
        }
    }

    private User getAuthenticatedUser(ThreadContext threadContext) {
        User user = threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
        if (user == null) {
            throw new OpenSearchSecurityException("User is not authenticated.");
        }
        return user;
    }

    private Map<String,Object>  analyzeImpact (
            Map<String, Object> currentRoles,
            Map<String, Object> currentRoleMappings,
            Map<String, Object> currentSecurityConfig,
            Map<String, Object> currentActionGroups,
            Map<String, Object> proposedRoles,
            Map<String, Object> proposedRoleMappings,
            Map<String, Object> proposedSecurityConfig,
            Map<String, Object> proposedActionGroups
    )
    {
        Map<String, Object> result = new HashMap<>();

        result.put("RoleModifications", getRoleModifications(proposedRoles, currentRoles));
        result.put("IndexAccessChanges", getIndexAccessChanges(proposedRoles, currentRoles));
        result.put("ClusterPermissionChanges", getClusterPermissionChanges(proposedRoles, currentRoles));
        result.put("TenantAccessChanges", getTenantAccessChanges(proposedRoles, currentRoles));
        result.put("HighImpactFindings", highImpactChanges(proposedSecurityConfig,proposedRoles,proposedRoleMappings));
        result.put("PerformanceRiskFindings", performanceRiskFindings(proposedRoles, currentRoles));
        result.put("ConflictingPermissionChanges", conflictingPermissionChanges(proposedRoles,proposedActionGroups,proposedRoleMappings,currentRoles,currentRoleMappings,currentActionGroups));
        result.put("InvalidConfigurations", invalidConfigurations(proposedSecurityConfig));
//        result.put("UserAccessChanges", getUserAccessDiff(proposedSecurityConfig, currentSecurityConfig));
//        result.put("ApiEndpointChanges", apiEndpointChanges(proposedSecurityConfig, currentSecurityConfig));

        return result;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getRoleModifications(Map<String, Object> proposedRoles, Map<String, Object> currentRoles) {
        List<Map<String, Object>> roleModifications = new ArrayList<>();
        for (String roleName : proposedRoles.keySet()) {
            Map<String, Object> newRole = (Map<String, Object>) proposedRoles.get(roleName);
            Map<String, Object> oldRole = (Map<String, Object>) currentRoles.get(roleName);

            if (oldRole == null) {
                roleModifications.add(Map.of(
                        "role", roleName,
                        "changeType", "added",
                        "details", newRole
                ));
            } else if (!newRole.equals(oldRole)) {
                roleModifications.add(Map.of(
                        "role", roleName,
                        "changeType", "modified",
                        "old", oldRole,
                        "new", newRole
                ));
            }
        }

        // Check for removed roles
        for (String roleName : currentRoles.keySet()) {
            if (!proposedRoles.containsKey(roleName)) {
                roleModifications.add(Map.of(
                        "role", roleName,
                        "changeType", "removed",
                        "details", currentRoles.get(roleName)
                ));
            }
        }

        return roleModifications;

    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getIndexAccessChanges(Map<String, Object> proposedRoles, Map<String, Object> currentRoles) {
        List<Map<String, Object>> indexAccessChanges = new ArrayList<>();
        for (String roleName : proposedRoles.keySet()) {
            Map<String, Object> newRole = (Map<String, Object>) proposedRoles.get(roleName);
            Map<String, Object> oldRole = (Map<String, Object>) currentRoles.get(roleName);
            List<Map<String, Object>> oldIndexPerms = oldRole != null
                    ? (List<Map<String, Object>>) oldRole.getOrDefault("index_permissions", List.of())
                    : List.of();
            List<Map<String, Object>> newIndexPerms = (List<Map<String, Object>>) newRole.getOrDefault("index_permissions", List.of());

            Map<String, Set<String>> oldIndexAccess = extractIndexAccess(oldIndexPerms);
            Map<String, Set<String>> newIndexAccess = extractIndexAccess(newIndexPerms);

            for (String index : newIndexAccess.keySet()) {
                if (!oldIndexAccess.containsKey(index)) {
                    indexAccessChanges.add(Map.of("index", index, "changes", List.of("Added access for role '" + roleName + "'")));
                } else {
                    Set<String> added = new HashSet<>(newIndexAccess.get(index));
                    added.removeAll(oldIndexAccess.get(index));
                    if (!added.isEmpty()) {
                        indexAccessChanges.add(Map.of("index", index, "changes", List.of("Role '" + roleName + "' added: " + added)));
                    }

                    Set<String> removed = new HashSet<>(oldIndexAccess.get(index));
                    removed.removeAll(newIndexAccess.get(index));
                    if (!removed.isEmpty()) {
                        indexAccessChanges.add(Map.of("index", index, "changes", List.of("Role '" + roleName + "' removed: " + removed)));
                    }
                }
            }

            for (String index : oldIndexAccess.keySet()) {
                if (!newIndexAccess.containsKey(index)) {
                    indexAccessChanges.add(Map.of("index", index, "changes", List.of("Removed access for role '" + roleName + "'")));
                }
            }

        }
        return indexAccessChanges;

    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getClusterPermissionChanges(Map<String, Object> proposedRoles, Map<String, Object> currentRoles) {
        List<Map<String, Object>> clusterPermissionChanges = new ArrayList<>();
        for (String roleName : proposedRoles.keySet()) {
            Map<String, Object> newRole = (Map<String, Object>) proposedRoles.get(roleName);
            Map<String, Object> oldRole = (Map<String, Object>) currentRoles.get(roleName);

            List<String> oldClusterPerms = oldRole != null
                    ? (List<String>) oldRole.getOrDefault("cluster_permissions", List.of())
                    : List.of();
            List<String> newClusterPerms = (List<String>) newRole.getOrDefault("cluster_permissions", List.of());

            Set<String> addedCluster = new HashSet<>(newClusterPerms);
            addedCluster.removeAll(oldClusterPerms);

            Set<String> removedCluster = new HashSet<>(oldClusterPerms);
            removedCluster.removeAll(newClusterPerms);

            if (!addedCluster.isEmpty() || !removedCluster.isEmpty()) {
                clusterPermissionChanges.add(
                        Map.of("role", roleName, "added", new ArrayList<>(addedCluster), "removed", new ArrayList<>(removedCluster))
                );
            }
        }
        return clusterPermissionChanges;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> getTenantAccessChanges(Map<String, Object> proposedRoles, Map<String, Object> currentRoles) {
        List<Map<String, Object>> tenantAccessChanges = new ArrayList<>();
        for (String roleName : proposedRoles.keySet()) {
            Map<String, Object> newRole = (Map<String, Object>) proposedRoles.get(roleName);
            Map<String, Object> oldRole = (Map<String, Object>) currentRoles.get(roleName);
            List<Map<String, Object>> oldTenants = oldRole != null
                    ? (List<Map<String, Object>>) oldRole.getOrDefault("tenant_permissions", List.of())
                    : List.of();
            List<Map<String, Object>> newTenants = (List<Map<String, Object>>) newRole.getOrDefault("tenant_permissions", List.of());

            List<String> tenantChanges = new ArrayList<>();

            for (Map<String, Object> oldPerm : normalizeTenantPerms(oldTenants)) {
                for (Map<String, Object> newPerm : normalizeTenantPerms(newTenants)) {
                    Set<String> oldPatterns = (Set<String>) oldPerm.get("tenant_patterns");
                    Set<String> newPatterns = (Set<String>) newPerm.get("tenant_patterns");

                    Set<String> oldActions = (Set<String>) oldPerm.get("allowed_actions");
                    Set<String> newActions = (Set<String>) newPerm.get("allowed_actions");

                    if (oldActions.equals(newActions) && !oldPatterns.equals(newPatterns)) {
                        tenantChanges.add("Changed tenant_patterns from " + oldPatterns + " to " + newPatterns + " for allowed_actions " + newActions);
                    } else if (!oldActions.equals(newActions) && oldPatterns.equals(newPatterns)) {
                        tenantChanges.add("Changed allowed_actions from " + oldActions + " to " + newActions + " for tenant_patterns " + oldPatterns);
                    } else if (!oldActions.equals(newActions) && !oldPatterns.equals(newPatterns)) {
                        tenantChanges.add("Changed tenant_permissions: patterns " + oldPatterns + " → " + newPatterns + ", actions " + oldActions + " → " + newActions);
                    }
                }
            }

            if (!tenantChanges.isEmpty()) {
                tenantAccessChanges.add(Map.of("role", roleName, "changes", tenantChanges));
            }

        }
        return tenantAccessChanges;
    }

    private List<Map<String, Object>> highImpactChanges(Map<String, Object> proposedSecurityConfig,Map<String, Object> proposedRoles, Map<String, Object> proposedRoleMappings) {
        List<Map<String, Object>> highImpactFindings = new ArrayList<>();

        Map<String, Object> finding;

        finding = checkDoNotFailOnForbidden(proposedSecurityConfig);
        if (!finding.isEmpty()) {
            highImpactFindings.add(finding);
        }

        finding = checkMultiRoleSpan(proposedSecurityConfig);
        if (!finding.isEmpty()) highImpactFindings.add(finding);

        finding = checkAnonymousAuthEnabled(proposedSecurityConfig);
        if (!finding.isEmpty()) highImpactFindings.add(finding);

        finding = detectIndexPatternWildcardWithDLS(proposedRoles);
        if (!finding.isEmpty()) highImpactFindings.add(finding);

        List<Map<String, Object>> wildcardFindings = detectWildcardAccessForNonAdminUsers(proposedRoles, proposedRoleMappings);
        if (!wildcardFindings.isEmpty()) highImpactFindings.addAll(wildcardFindings);

        return highImpactFindings;
    }

    private Map<String, Object> checkDoNotFailOnForbidden(Map<String, Object> proposedSecurityConfig) {

        Object dynamic = proposedSecurityConfig.get("dynamic");
        if (!(dynamic instanceof Map)) return Map.of();
        Object value = ((Map<?, ?>) dynamic).get("do_not_fail_on_forbidden");
        if (value instanceof Boolean && (Boolean) value) {
            Map<String, Object> details = Map.of(
                    "impact","Allows operations to proceed even when access should be forbidden, potentially exposing sensitive data or allowing unauthorized modifications",
                    "affectedComponents",List.of("All indices", "Search operations", "Document operations", "Cluster operations"),
                    "securityImplications",List.of(
                            "Bypass of access control mechanisms",
                            "Potential data leakage",
                            "Unauthorized data modifications",
                            "Violation of principle of least privilege"
                    ),
                    "complianceImpact",List.of(
                            "May violate data protection regulations (e.g., GDPR, HIPAA)"
                    ),
                    "recommendation","Set do_not_fail_on_forbidden to false"
            );

            return Map.of(
                    "severity","HIGH",
                    "category","Access Control",
                    "setting","do_not_fail_on_forbidden",
                    "description","do_not_fail_on_forbidden set to true allows operations to continue on forbidden access",
                    "details",details
            );

        }
        return Map.of();
    }

    private Map<String, Object> checkMultiRoleSpan(Map<String, Object> proposedSecurityConfig) {
        Object dynamic = proposedSecurityConfig.get("dynamic");
        if (!(dynamic instanceof Map)) return Map.of();
        Object value = ((Map<?, ?>) dynamic).get("multi_rolespan_enabled");

        if (value instanceof Boolean && !(Boolean) value) {
            Map<String, Object> details = Map.of(
                    "impact", "Disabling multi_rolespan restricts users to a single role during access evaluation, reducing flexibility and permission coverage.",
                    "affectedComponents", List.of("Users with multiple roles", "Access control resolution", "Index and cluster-level operations"),
                    "securityImplications", List.of(
                            "May cause unexpected access denials if required permissions are split across roles",
                            "Potential disruptions in user workflows"
                    ),
                    "complianceImpact", List.of(
                            "Could violate internal access policy if multi-role mapping is expected"
                    ),
                    "recommendation", "Set multi_rolespan_enabled to true to allow permission aggregation from multiple roles"
            );

            return Map.of(
                    "severity", "HIGH",
                    "category", "Access Control",
                    "setting", "multi_rolespan_enabled",
                    "description", "multi_rolespan_enabled set to false limits users to a single role, which can reduce access flexibility",
                    "details", details
            );
        }

        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> checkAnonymousAuthEnabled(Map<String, Object> proposedSecurityConfig) {

        Map<String, Object> dynamic = (Map<String, Object>) proposedSecurityConfig.get("dynamic");
        if (dynamic == null) return Map.of();

        Map<String, Object> http = (Map<String, Object>) dynamic.get("http");
        if (http == null) return Map.of();

        Object value = http.get("anonymous_auth_enabled");

        if (value instanceof Boolean && (Boolean) value) {
            Map<String, Object> details = Map.of(
                    "impact", "Allows unauthenticated users to access the cluster, leading to potential data exposure and unauthorized access.",
                    "affectedComponents", List.of("All public endpoints", "Cluster APIs", "Index data"),
                    "securityImplications", List.of(
                            "Bypass of authentication and access control",
                            "No audit trail for anonymous users",
                            "Increased risk of data leaks and misuse"
                    ),
                    "complianceImpact", List.of(
                            "Violates security best practices",
                            "May breach compliance regulations (e.g., GDPR, HIPAA)"
                    ),
                    "recommendation", "Set anonymous_auth_enabled to false to restrict unauthenticated access"
            );

            return Map.of(
                    "severity", "HIGH",
                    "category", "Authentication Settings",
                    "setting", "anonymous_auth_enabled",
                    "description", "anonymous_auth_enabled is set to true, allowing unauthenticated access to the cluster",
                    "details", details
            );

        }
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> detectIndexPatternWildcardWithDLS(Map<String, Object> proposedRoles) {

        for (String roleName : proposedRoles.keySet()) {
            Map<String, Object> role = (Map<String, Object>) proposedRoles.get(roleName);
            List<Map<String, Object>> indexPerms = (List<Map<String, Object>>) role.getOrDefault("index_permissions", List.of());

            for (Map<String, Object> perm : indexPerms) {
                List<String> patterns = (List<String>) perm.getOrDefault("index_patterns", List.of());

                if (patterns.contains("*")) {
                    Object dls = perm.get("dls");
                    if (dls!=null && dls instanceof String && !((String) dls).isEmpty()) {
                        return Map.of(
                                "severity", "HIGH",
                                "category", "Access Control",
                                "role", roleName,
                                "description", "Index pattern '*' with DLS enabled can cause issues in Kibana login and dashboards",
                                "recommendations", List.of(
                                        "Avoid using wildcard '*' with DLS settings",
                                        "Use more specific index patterns to scope DLS properly",
                                        "Test Kibana dashboards for access issues when using '*' with DLS"
                                )
                        );
                    }
                }
            }
        }

        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> detectWildcardAccessForNonAdminUsers(Map<String, Object> roles, Map<String, Object> roleMappings) {
        List<Map<String, Object>> findings = new ArrayList<>();
        Set<String> adminRoles = Set.of("all_access", "security_manager");

        // Map users to their roles
        Map<String, List<String>> userToRoles = new HashMap<>();
        for (Map.Entry<String, Object> entry : roleMappings.entrySet()) {
            String role = entry.getKey();
            Map<String, Object> mapping = (Map<String, Object>) entry.getValue();
            List<String> users = (List<String>) mapping.getOrDefault("users", List.of());

            for (String user : users) {
                userToRoles.computeIfAbsent(user, k -> new ArrayList<>()).add(role);
            }
        }

        // Check each user's roles
        for (Map.Entry<String, List<String>> entry : userToRoles.entrySet()) {
            String user = entry.getKey();
            List<String> assignedRoles = entry.getValue();

            // Skip entire user if they have any admin role
            if (assignedRoles.stream().anyMatch(adminRoles::contains)) {
                continue;
            }

            for (String roleName : assignedRoles) {
                Map<String, Object> roleDef = (Map<String, Object>) roles.get(roleName);
                if (roleDef == null) continue;

                List<Map<String, Object>> indexPerms = (List<Map<String, Object>>) roleDef.getOrDefault("index_permissions", List.of());
                for (Map<String, Object> perm : indexPerms) {
                    List<String> patterns = (List<String>) perm.getOrDefault("index_patterns", List.of());
                    if (patterns.contains("*")) {
                        findings.add(buildFinding(user, roleName, "*", "index_patterns"));
                    }
                }

                List<Map<String, Object>> tenantPerms = (List<Map<String, Object>>) roleDef.getOrDefault("tenant_permissions", List.of());
                for (Map<String, Object> perm : tenantPerms) {
                    List<String> patterns = (List<String>) perm.getOrDefault("tenant_patterns", List.of());
                    if (patterns.contains("*")) {
                        findings.add(buildFinding(user, roleName, "*", "tenant_patterns"));
                    }
                }
            }
        }

        return findings;
    }

    private Map<String, Object> buildFinding(String user, String role, String pattern, String type) {
        return Map.of(
                "severity", "HIGH",
                "category", "Privilege Escalation Risk",
                "description", "Wildcard access granted to non-admin user",
                "details", Map.of(
                        "user", user,
                        "role", role,
                        "patternType", type,
                        "wildcardPattern", pattern,
                        "impact", "Excessive privileges granted to non-admin role",
                        "recommendation", List.of("Avoid assigning '*' patterns to non-admin users",
                                "Define specific permissions required for role")
                )
        );
    }


    private List<Map<String, Object>> performanceRiskFindings(Map<String, Object> proposedRoles, Map<String, Object> currentRoles){
        List<Map<String, Object>> performanceRisk = new ArrayList<>();
        List<Map<String, Object>> perfFindings = detectBroadAccessPatternRisks(proposedRoles, currentRoles);
        if (!perfFindings.isEmpty()) {
            performanceRisk.addAll(perfFindings);
        }
        return performanceRisk;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> detectBroadAccessPatternRisks(Map<String, Object> proposedRoles, Map<String, Object> currentRoles) {
        List<Map<String, Object>> findings = new ArrayList<>();

        for (String role : proposedRoles.keySet()) {
            Map<String, Object> newRole = (Map<String, Object>) proposedRoles.get(role);
            Map<String, Object> oldRole = (Map<String, Object>) currentRoles.getOrDefault(role, Map.of());

            List<Map<String, Object>> newIndexPerms = (List<Map<String, Object>>) newRole.getOrDefault("index_permissions", List.of());
            List<Map<String, Object>> oldIndexPerms = (List<Map<String, Object>>) oldRole.getOrDefault("index_permissions", List.of());

            Set<String> newPatterns = new HashSet<>();
            for (Map<String, Object> newPerm : newIndexPerms) {
                newPatterns.addAll((List<String>) newPerm.getOrDefault("index_patterns", List.of()));
            }

            Set<String> oldPatterns = new HashSet<>();
            for (Map<String, Object> oldPerm : oldIndexPerms) {
                oldPatterns.addAll((List<String>) oldPerm.getOrDefault("index_patterns", List.of()));
            }

            if (!oldPatterns.contains("*") && newPatterns.contains("*")) {
                Map<String, Object> finding = Map.of(
                        "category", "Role-Based Access Control",
                        "performanceImpact", "High",
                        "role", role,
                        "description", "Use of overly broad wildcard '*' in index patterns can significantly increase privilege evaluation time",
                        "recommendations", List.of(
                                "Use more specific index patterns (e.g., 'logs-*' instead of '*')",
                                "Avoid unnecessary wildcard usage in roles to improve performance",
                                "Consider using index aliases or separate roles with specific permissions"
                        )
                );
                findings.add(finding);
            }
        }
        return findings;
    }

    private List<Map<String, Object>> conflictingPermissionChanges(Map<String, Object> proposedRoles, Map<String, Object> proposedActionGroups,Map<String,Object> proposedRoleMappings,Map<String,Object> currentRoles,Map<String,Object> currentRoleMappings,Map<String,Object> currentActionGroups) {
        List<Map<String, Object>> findings = new ArrayList<>();

        List<Map<String, Object>> recursionFindings = detectActionGroupCircularReference(proposedActionGroups);
        if (!recursionFindings.isEmpty()) {
            findings.addAll(recursionFindings);
        }

        List<Map<String,Object>> userPermissions=detectUserPermissionConflicts(proposedRoles, proposedRoleMappings, currentRoles, currentRoleMappings);
        if (!userPermissions.isEmpty()) {
            findings.addAll(userPermissions);
        }

        List<Map<String, Object>> wildcardConflicts = detectWildcardPermissionConflicts(proposedRoles);
        if (!wildcardConflicts.isEmpty()) {
            findings.addAll(wildcardConflicts);
        }

        List<Map<String, Object>> UserPermissionReductionConflicts=detectUserPermissionReductionConflicts(proposedRoles, proposedRoleMappings, currentRoles, currentRoleMappings);
        if (!UserPermissionReductionConflicts.isEmpty()) {
            findings.addAll(UserPermissionReductionConflicts);
        }

        return findings;
    }

    private List<Map<String, Object>> detectActionGroupCircularReference(Map<String, Object> actionGroups) {
        List<Map<String, Object>> findings = new ArrayList<>();

        for (String groupName : actionGroups.keySet()) {
            Map<String, Object> finding = detectCircularReference(actionGroups, groupName, new HashSet<>());
            if (!finding.isEmpty()) {
                findings.add(finding);
            }
        }

        return findings;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> detectCircularReference(Map<String, Object> sourceMap, String currentKey, Set<String> pathSet) {
        if (pathSet.contains(currentKey)) {
            return Map.of(
                    "category",  "ActionGroup Circular Reference",
                    "severity", "High",
                    "action_group", currentKey,
                    "description", "Circular reference detected in action group " + currentKey + "'",
                    "recommendations", List.of(
                            "Remove circular references in allowed_actions",
                            "Avoid self-referencing or mutual references"
                    )
            );
        }

        pathSet.add(currentKey);

        Map<String, Object> details = (Map<String, Object>) sourceMap.get(currentKey);
        if (details == null || details.isEmpty()) return Map.of();

        List<String> allowedActions = (List<String>) details.getOrDefault("allowed_actions", List.of());

        for (String action : allowedActions) {
            if (sourceMap.containsKey(action)) {
                Map<String, Object> result = detectCircularReference(sourceMap, action, new HashSet<>(pathSet));
                if (!result.isEmpty()) return result;
            }
        }

        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> detectUserPermissionConflicts(Map<String, Object> roles, Map<String, Object> roleMappings, Map<String,Object> currentRoles, Map<String,Object> currentRoleMappings) {
        Map<String, List<String>> userToRoles = new HashMap<>();

        // Map users to their roles
        for (Map.Entry<String, Object> entry : roleMappings.entrySet()) {
            String role = entry.getKey();
            Map<String, Object> mapping = (Map<String, Object>) entry.getValue();
            List<String> users = (List<String>) mapping.getOrDefault("users", List.of());

            for (String user : users) {
                userToRoles.computeIfAbsent(user, k -> new ArrayList<>()).add(role);
            }
        }

        List<Map<String, Object>> conflicts = new ArrayList<>();

        //Check each user's permissions
        for (Map.Entry<String, List<String>> userEntry : userToRoles.entrySet()) {
            String user = userEntry.getKey();
            List<String> assignedRoles = userEntry.getValue();

            Map<String, Map<String, Set<String>>> indexAccessMap = new HashMap<>();

            for (String roleName : assignedRoles) {
                Map<String, Object> roleDef = (Map<String, Object>) roles.get(roleName);
                if (roleDef == null) continue;

                List<Map<String, Object>> indexPerms = (List<Map<String, Object>>) roleDef.getOrDefault("index_permissions", List.of());
                Map<String, Set<String>> extractedAccess = extractIndexAccess(indexPerms);

                for (Map.Entry<String, Set<String>> entry : extractedAccess.entrySet()) {
                    String indexPattern = entry.getKey();
                    Set<String> actions = entry.getValue();

                    indexAccessMap.computeIfAbsent(indexPattern, k -> new HashMap<>())
                            .computeIfAbsent(roleName, k -> new HashSet<>())
                            .addAll(actions);
                }
            }

            // Detect conflicts for user
            for (Map.Entry<String, Map<String, Set<String>>> indexEntry : indexAccessMap.entrySet()) {
                String index = indexEntry.getKey();
                Map<String, Set<String>> roleToActions = indexEntry.getValue();
                Set<Set<String>> comparedRoles = new HashSet<>();
                for (String roleA : roleToActions.keySet()) {
                    for (String roleB : roleToActions.keySet()) {
                        if (!roleA.equals(roleB)) {
                            Set<String> pair = new HashSet<>(List.of(roleA, roleB));
                            if (comparedRoles.contains(pair)) continue;
                            Set<String> actionsA = roleToActions.get(roleA);
                            Set<String> actionsB = roleToActions.get(roleB);

                            Set<String> conflictingActions = new HashSet<>();

                            if (actionsA.contains("*") && !actionsB.contains("*")) {
                                conflictingActions.addAll(actionsB);
                            } else if (actionsB.contains("*") && !actionsA.contains("*")) {
                                conflictingActions.addAll(actionsA);
                            } else {
                                Set<String> diff = new HashSet<>(actionsA);
                                diff.removeAll(actionsB);
                                if (!diff.isEmpty()) {
                                    conflictingActions.addAll(diff);
                                }
                            }

                            if (!conflictingActions.isEmpty()) {
                                conflicts.add(Map.of(
                                        "user", user,
                                        "severity", "HIGH",
                                        "category", "Role-Based Access Control",
                                        "description", "Conflicting permissions in role definitions",
                                        "details", Map.of(
                                                "conflictingRoles", List.of(roleA, roleB),
                                                "affectedResource", List.of(index),
                                                "conflictingActions", conflictingActions,
                                                "impact", "Unclear permissions for users with both roles",
                                                "recommendation", "Review and adjust permissions for affected roles"
                                        )
                                ));
                            }
                            comparedRoles.add(pair);
                        }
                    }
                }
            }
        }

        return conflicts;
    }

    private List<Map<String, Object>> detectWildcardPermissionConflicts(Map<String, Object> proposedRoles) {
        List<Map<String, Object>> conflicts = new ArrayList<>();

        conflicts.addAll(detectPermissionConflicts(proposedRoles, "index_permissions", "index_patterns", "allowed_actions", "Index Pattern Conflict"));
        conflicts.addAll(detectDLSAndFLSConflicts(proposedRoles, "dls"));
        conflicts.addAll(detectDLSAndFLSConflicts(proposedRoles, "fls"));
        conflicts.addAll(detectPermissionConflicts(proposedRoles, "tenant_permissions", "tenant_patterns", "allowed_actions", "Tenant Access Conflict"));

        return conflicts;

    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> detectPermissionConflicts(Map<String, Object> roles, String permissionsKey, String patternsKey, String actionKey, String category)
    {
        List<Map<String, Object>> conflicts = new ArrayList<>();
        Set<Set<String>> compared = new HashSet<>();

        for (String roleA : roles.keySet()) {
            Map<String, Object> defA = (Map<String, Object>) roles.get(roleA);
            List<Map<String, Object>> permsA = (List<Map<String, Object>>) defA.getOrDefault(permissionsKey, List.of());

            for (String roleB : roles.keySet()) {
                if (roleA.equals(roleB)) continue;
                Set<String> rolePair = new HashSet<>(List.of(roleA, roleB));
                if (!compared.add(rolePair)) continue;

                Map<String, Object> defB = (Map<String, Object>) roles.get(roleB);
                List<Map<String, Object>> permsB = (List<Map<String, Object>>) defB.getOrDefault(permissionsKey, List.of());

                for (Map<String, Object> permA : permsA) {
                    List<String> patternsA = (List<String>) permA.getOrDefault(patternsKey, List.of());
                    Set<String> actionsA = new HashSet<>((List<String>) permA.getOrDefault(actionKey, List.of()));

                    for (Map<String, Object> permB : permsB) {
                        List<String> patternsB = (List<String>) permB.getOrDefault(patternsKey, List.of());
                        Set<String> actionsB = new HashSet<>((List<String>) permB.getOrDefault(actionKey, List.of()));

                        for (String patternA : patternsA) {
                            for (String patternB : patternsB) {
                                if (isBroader(patternA, patternB)) {
                                    Set<String> diff = new HashSet<>();
                                    if (actionsA.contains("*") && !actionsB.contains("*")) {
                                        diff.addAll(actionsB);
                                    } else if (actionsB.contains("*") && !actionsA.contains("*")) {
                                        diff.addAll(actionsA);
                                    } else {
                                        diff = new HashSet<>(actionsA);
                                        diff.removeAll(actionsB);
                                    }
                                    if (!diff.isEmpty()) {
                                        conflicts.add(Map.of(
                                                "severity", "MEDIUM",
                                                "category", category,
                                                "description", "Broader pattern has more privileges than a specific subset",
                                                "details", Map.of(
                                                        "conflictingRoles", List.of(roleA, roleB),
                                                        "broadPattern", patternA,
                                                        "narrowPattern", patternB,
                                                        "conflictingActions", diff,
                                                        "impact", "User may get escalated access on specific pattern due to broader pattern",
                                                        "recommendation", "Ensure consistent permissions across roles with overlapping patterns to prevent unintended privilege escalation."
                                                )
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return conflicts;

    }

    private boolean isBroader(String broadPattern, String specificPattern) {
        if (broadPattern.equals("*")) return true;

        if (broadPattern.endsWith("*")) {
            String prefix = broadPattern.substring(0, broadPattern.length() - 1);
            return specificPattern.startsWith(prefix) && !specificPattern.equals(broadPattern);
        }

        return false;
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> detectUserPermissionReductionConflicts(
            Map<String, Object> currentRoles,
            Map<String, Object> currentRoleMappings,
            Map<String, Object> proposedRoles,
            Map<String, Object> proposedRoleMappings) {

        Map<String, List<String>> currentUserToRoles = new HashMap<>();
        for (Map.Entry<String, Object> entry : currentRoleMappings.entrySet()) {
            String role = entry.getKey();
            Map<String, Object> mapping = (Map<String, Object>) entry.getValue();
            List<String> users = (List<String>) mapping.getOrDefault("users", List.of());
            for (String user : users) {
                currentUserToRoles.computeIfAbsent(user, k -> new ArrayList<>()).add(role);
            }
        }

        Map<String, List<String>> proposedUserToRoles = new HashMap<>();
        for (Map.Entry<String, Object> entry : proposedRoleMappings.entrySet()) {
            String role = entry.getKey();
            Map<String, Object> mapping = (Map<String, Object>) entry.getValue();
            List<String> users = (List<String>) mapping.getOrDefault("users", List.of());
            for (String user : users) {
                proposedUserToRoles.computeIfAbsent(user, k -> new ArrayList<>()).add(role);
            }
        }

        Set<String> allUsers = new HashSet<>();
        allUsers.addAll(currentUserToRoles.keySet());
        allUsers.addAll(proposedUserToRoles.keySet());

        List<Map<String, Object>> conflicts = new ArrayList<>();

        for (String user : allUsers) {
            Map<String, Set<String>> currentAccess = new HashMap<>();
            for (String role : currentUserToRoles.getOrDefault(user, List.of())) {
                Map<String, Object> roleDef = (Map<String, Object>) currentRoles.get(role);
                if (roleDef == null) continue;

                List<Map<String, Object>> indexPerms = (List<Map<String, Object>>) roleDef.getOrDefault("index_permissions", List.of());
                Map<String, Set<String>> extracted = extractIndexAccess(indexPerms);

                for (Map.Entry<String, Set<String>> entry : extracted.entrySet()) {
                    currentAccess.computeIfAbsent(entry.getKey(), k -> new HashSet<>()).addAll(entry.getValue());
                }
            }

            Map<String, Set<String>> proposedAccess = new HashMap<>();
            for (String role : proposedUserToRoles.getOrDefault(user, List.of())) {
                Map<String, Object> roleDef = (Map<String, Object>) proposedRoles.get(role);
                if (roleDef == null) continue;

                List<Map<String, Object>> indexPerms = (List<Map<String, Object>>) roleDef.getOrDefault("index_permissions", List.of());
                Map<String, Set<String>> extracted = extractIndexAccess(indexPerms);

                for (Map.Entry<String, Set<String>> entry : extracted.entrySet()) {
                    proposedAccess.computeIfAbsent(entry.getKey(), k -> new HashSet<>()).addAll(entry.getValue());
                }
            }

            for (String indexPattern : currentAccess.keySet()) {
                Set<String> currentActions = currentAccess.getOrDefault(indexPattern, Set.of());
                Set<String> proposedActions = proposedAccess.getOrDefault(indexPattern, Set.of());

                Set<String> removed = new HashSet<>(currentActions);
                removed.removeAll(proposedActions);

                if (!removed.isEmpty()) {
                    conflicts.add(Map.of(
                            "user", user,
                            "severity", "Medium",
                            "category", "Permission Reduction",
                            "description", "User had permissions that are removed in the proposed config",
                            "details", Map.of(
                                    "affectedResource", indexPattern,
                                    "removedActions", removed,
                                    "impact", "User will lose previously allowed actions",
                                    "recommendation", "Review changes to ensure this reduction is intended"
                            )
                    ));
                }
            }
        }

        return conflicts;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> detectDLSAndFLSConflicts(Map<String, Object> roles, String conflictType) {
        List<Map<String, Object>> conflicts = new ArrayList<>();
        Set<Set<String>> compared = new HashSet<>();

        for (String role1 : roles.keySet()) {
            Map<String, Object> def1 = (Map<String, Object>) roles.get(role1);
            List<Map<String, Object>> perms1 = (List<Map<String, Object>>) def1.getOrDefault("index_permissions", List.of());

            for (String role2 : roles.keySet()) {
                if (role1.equals(role2)) continue;
                Set<String> rolePair = Set.of(role1, role2);
                if (!compared.add(rolePair)) continue;

                Map<String, Object> def2 = (Map<String, Object>) roles.get(role2);
                List<Map<String, Object>> perms2 = (List<Map<String, Object>>) def2.getOrDefault("index_permissions", List.of());

                for (Map<String, Object> perm1 : perms1) {
                    List<String> patterns1 = (List<String>) perm1.getOrDefault("index_patterns", List.of());
                    Set<String> actions1 = new HashSet<>((List<String>) perm1.getOrDefault("allowed_actions", List.of()));

                    for (Map<String, Object> perm2 : perms2) {
                        List<String> patterns2 = (List<String>) perm2.getOrDefault("index_patterns", List.of());
                        Set<String> actions2 = new HashSet<>((List<String>) perm2.getOrDefault("allowed_actions", List.of()));

                        for (String pattern1 : patterns1) {
                            for (String pattern2 : patterns2) {
                                if (!(isBroader(pattern1, pattern2) || isBroader(pattern2, pattern1))) continue;

                                if ("dls".equalsIgnoreCase(conflictType)) {
                                    String dls1 = (String) perm1.getOrDefault("dls", "");
                                    String dls2 = (String) perm2.getOrDefault("dls", "");
                                    if (!dls1.isEmpty() && !dls2.isEmpty() && !dls1.equals(dls2)) {
                                        conflicts.add(Map.of(
                                                "severity", "HIGH",
                                                "category", "DLS Conflict",
                                                "description", "Different DLS settings for overlapping index patterns",
                                                "details", Map.of(
                                                        "roles", Map.of(
                                                                role1, Map.of("pattern", pattern1, "dls", dls1, "actions", actions1),
                                                                role2, Map.of("pattern", pattern2, "dls", dls2, "actions", actions2)
                                                        ),
                                                        "impact", "User may get conflicting document-level access",
                                                        "recommendations", List.of(
                                                                "Align DLS configurations across roles",
                                                                "Consider using a single role for DLS access",
                                                                "Review document-level security requirements"
                                                        )
                                                )
                                        ));
                                    }
                                }

                                if ("fls".equalsIgnoreCase(conflictType)) {
                                    List<String> fls1 = (List<String>) perm1.getOrDefault("fls", List.of());
                                    List<String> fls2 = (List<String>) perm2.getOrDefault("fls", List.of());
                                    if (!fls1.isEmpty() && !fls2.isEmpty() && !fls1.equals(fls2)) {
                                        conflicts.add(Map.of(
                                                "severity", "HIGH",
                                                "category", "FLS Conflict",
                                                "description", "Different FLS settings for overlapping index patterns",
                                                "details", Map.of(
                                                        "roles", Map.of(
                                                                role1, Map.of("pattern", pattern1, "fls", fls1, "actions", actions1),
                                                                role2, Map.of("pattern", pattern2, "fls", fls2, "actions", actions2)
                                                        ),
                                                        "impact", "User may get conflicting field-level access",
                                                        "recommendations", List.of(
                                                                "Align FLS configurations across roles",
                                                                "Consider using a single role for FLS access",
                                                                "Review field-level security requirements"
                                                        )
                                                )
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return conflicts;
    }

    private List<Map<String, Object>> invalidConfigurations(Map<String, Object> proposedSecurityConfig) {
        List<Map<String, Object>> invalidConfig = new ArrayList<>();

        Map<String, Object> basicAuthIssueFinding = checkBasicAuthConfiguration(proposedSecurityConfig);
        if (!basicAuthIssueFinding.isEmpty()) {
            invalidConfig.add(basicAuthIssueFinding);
        }

        List<Map<String, Object>> ldapFindings = checkLDAPAuthConfiguration(proposedSecurityConfig);
        invalidConfig.addAll(ldapFindings);
        return invalidConfig;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> checkBasicAuthConfiguration(Map<String, Object> proposedSecurityConfig) {
        if (proposedSecurityConfig == null) return Map.of();

        Map<String, Object> dynamic = (Map<String, Object>) proposedSecurityConfig.get("dynamic");
        if (dynamic == null) return Map.of();

        Map<String, Object> authc = (Map<String, Object>) dynamic.get("authc");
        if (authc == null) return Map.of();

        Map<String, Object> domain = (Map<String, Object>) authc.get("basic_internal_auth_domain");
        if (domain == null) return Map.of();

        Boolean httpEnabled = (Boolean) domain.get("http_enabled");
        Map<String, Object> httpAuth = (Map<String, Object>) domain.get("http_authenticator");
        if (httpAuth == null) return Map.of();

        String type = (String) httpAuth.get("type");
        Boolean challenge = (Boolean) httpAuth.get("challenge");

        if (Boolean.TRUE.equals(httpEnabled) &&
                "basic".equals(type) &&
                Boolean.FALSE.equals(challenge)) {

            return Map.of(
                    "severity", "CRITICAL",
                    "category", "Authentication",
                    "description", "Basic Authentication configured incorrectly",
                    "details", Map.of(
                            "configuredSettings", Map.of(
                                    "authMethod", "basic_auth",
                                    "enabled", true,
                                    "challenge", false
                            ),
                            "issue", "Basic auth is enabled but challenge is set to false",
                            "impact", "Users cannot enter credentials, making basic auth unusable",
                            "affectedComponents", List.of("HTTP API", "Kibana Access"),
                            "securityImplications", List.of(
                                    "Potential lockout of all basic auth users",
                                    "Unintended reliance on other authentication methods"
                            )
                    )
            );
        }

        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> checkLDAPAuthConfiguration(Map<String, Object> proposedSecurityConfig) {
        List<Map<String, Object>> findings = new ArrayList<>();

        Map<String, Object> dynamic = (Map<String, Object>) proposedSecurityConfig.getOrDefault("dynamic", Map.of());
        Map<String, Object> authcDomains = (Map<String, Object>) dynamic.getOrDefault("authc", Map.of());

        Map<String, Object> ldapConfig = (Map<String, Object>) authcDomains.get("ldap");
        if (ldapConfig == null) return findings;

        boolean httpEnabled = Boolean.TRUE.equals(ldapConfig.get("http_enabled"));
        if (!httpEnabled) return findings; // LDAP not enabled

        // Check if authenticator is set and is "basic"
        Map<String, Object> httpAuth = (Map<String, Object>) ldapConfig.getOrDefault("http_authenticator", Map.of());
        String authType = (String) httpAuth.getOrDefault("type", "");

        if (!"basic".equalsIgnoreCase(authType)) {
            findings.add(Map.of(
                    "severity", "MEDIUM",
                    "category", "LDAP Configuration",
                    "description", "LDAP is enabled but HTTP authenticator is not set to 'basic'.",
                    "impact", "LDAP auth may not function as expected without 'basic' type.",
                    "recommendation", "Set 'http_authenticator.type' to 'basic' for LDAP authentication."
            ));
        }

        // Check if base_dn is missing or empty
        Map<String, Object> backend = (Map<String, Object>) ldapConfig.getOrDefault("authentication_backend", Map.of());
        Map<String, Object> backendConfig = (Map<String, Object>) backend.getOrDefault("config", Map.of());
        String baseDn = (String) backendConfig.getOrDefault("base_dn", "");

        if (baseDn == null || baseDn.trim().isEmpty()) {
            findings.add(Map.of(
                    "severity", "HIGH",
                    "category", "LDAP Configuration",
                    "description", "LDAP is enabled but 'base_dn' is missing or empty.",
                    "impact", "LDAP directory lookup will fail due to missing base DN.",
                    "recommendation", "Specify a valid 'base_dn' in the LDAP backend configuration."
            ));
        }

        return findings;
    }

    private Map<String, Set<String>> extractIndexAccess(List<Map<String, Object>> indexPerms) {
        Map<String, Set<String>> result = new HashMap<>();
        for (Map<String, Object> perm : indexPerms) {
            @SuppressWarnings("unchecked")
            List<String> indexPatterns = (List<String>) perm.getOrDefault("index_patterns", List.of());
            @SuppressWarnings("unchecked")
            List<String> actions = (List<String>) perm.getOrDefault("allowed_actions", List.of());
            for (String pattern : indexPatterns) {
                result.computeIfAbsent(pattern, k -> new HashSet<>()).addAll(actions);
            }
        }
        return result;
    }

    private List<Map<String, Object>> normalizeTenantPerms(List<Map<String, Object>> tenantPerms) {
        List<Map<String, Object>> normalized = new ArrayList<>();
        for (Map<String, Object> perm : tenantPerms) {
            Map<String, Object> copy = new HashMap<>();

            Object tpObj = perm.getOrDefault("tenant_patterns", List.of());
            Object aaObj = perm.getOrDefault("allowed_actions", List.of());

            Set<String> tenantPatterns = new HashSet<>();
            if (tpObj instanceof List<?>) {
                for (Object item : (List<?>) tpObj) {
                    if (item instanceof String) {
                        tenantPatterns.add((String) item);
                    }
                }
            }

            Set<String> allowedActions = new HashSet<>();
            if (aaObj instanceof List<?>) {
                for (Object item : (List<?>) aaObj) {
                    if (item instanceof String) {
                        allowedActions.add((String) item);
                    }
                }
            }

            copy.put("tenant_patterns", tenantPatterns);
            copy.put("allowed_actions", allowedActions);

            normalized.add(copy);
        }
        return normalized;
    }

    @Override
    protected EndpointValidator createEndpointValidator() {
        return new EndpointValidator() {
            @Override
            public Endpoint endpoint() {
                return endpoint;
            }

            @Override
            public RestApiAdminPrivilegesEvaluator restApiAdminPrivilegesEvaluator() {
                return securityApiDependencies.restApiAdminPrivilegesEvaluator();
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigLoad(SecurityConfiguration securityConfiguration) {
                return ValidationResult.success(securityConfiguration);
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigDelete(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Delete is not supported on this endpoint"));
            }

            @Override
            public ValidationResult<SecurityConfiguration> onConfigChange(SecurityConfiguration securityConfiguration) {
                return ValidationResult.error(RestStatus.FORBIDDEN, forbiddenMessage("Changes are not allowed via Impact Analysis API"));
            }

            @Override
            public RequestContentValidator createRequestContentValidator(Object... params) {
                return RequestContentValidator.NOOP_VALIDATOR;
            }
        };
    }

}
