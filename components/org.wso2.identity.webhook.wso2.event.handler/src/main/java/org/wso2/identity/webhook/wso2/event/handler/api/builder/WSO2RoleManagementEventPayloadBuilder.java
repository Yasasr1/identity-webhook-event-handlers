/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.IdpGroup;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Permission;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.identity.webhook.common.event.handler.api.builder.RoleManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleDeletedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleGroupsUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleIdpGroupsUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RolePermissionsUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleMetaUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.GroupEntry;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.UserEntry;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleUsersUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.RoleAudience;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.RoleRef;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntConsumer;

import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.RoleManagement.ROLE_LIST_MAX_SIZE;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.AGENT_NAME_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_ROLES_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.USERNAME_CLAIM_URI;

/**
 * WSO2 Role Management Event Payload Builder.
 * Builds webhook event payloads for V2 role lifecycle events.
 */
public class WSO2RoleManagementEventPayloadBuilder implements RoleManagementEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2RoleManagementEventPayloadBuilder.class);

    @Override
    public EventPayload buildRoleCreatedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> props = eventData.getEventParams();
        String roleId = (String) props.get(IdentityEventConstants.EventProperty.ROLE_ID);
        String audience = (String) props.get(IdentityEventConstants.EventProperty.AUDIENCE);
        String audienceId = (String) props.get(IdentityEventConstants.EventProperty.AUDIENCE_ID);
        String tenantDomain = eventData.getTenantDomain();

        EnvelopeContext ctx = new EnvelopeContext();

        WSO2RoleCreatedEventPayload.RoleWithMembership role =
                enrichRole(new WSO2RoleCreatedEventPayload.RoleWithMembership(), roleId, tenantDomain);
        // Fallback to props-audience when RoleBasicInfo lookup did not populate it.
        if (role.getAudience() == null && StringUtils.isNotBlank(audience)) {
            role.setAudience(buildRoleAudience(audience, audienceId, null));
        }

        List<String> userIds = toStringList(props.get(IdentityEventConstants.EventProperty.USER_LIST));
        List<String> groupIds = toStringList(props.get(IdentityEventConstants.EventProperty.GROUP_LIST));
        List<String> permissionNames = toPermissionNames(props.get(IdentityEventConstants.EventProperty.PERMISSIONS));

        AbstractUserStoreManager userManager = getAbstractUserStoreManager(tenantDomain);
        role.setUsers(userIds.isEmpty() ? null : toEnrichedUserEntries(userIds, userManager));
        role.setGroups(groupIds.isEmpty() ? null : toEnrichedGroupEntries(groupIds, userManager));
        role.setPermissions(permissionNames.isEmpty() ? null : permissionNames);

        return new WSO2RoleCreatedEventPayload.Builder()
                .tenant(ctx.tenant)
                .organization(ctx.organization)
                .initiatorType(ctx.initiatorType)
                .initiatorIpAddress(ctx.initiatorIpAddress)
                .action(ctx.action)
                .role(role)
                .build();
    }

    @Override
    public EventPayload buildRoleMetaUpdatedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> props = eventData.getEventParams();
        String roleId = (String) props.get(IdentityEventConstants.EventProperty.ROLE_ID);
        String newRoleName = (String) props.get(IdentityEventConstants.EventProperty.NEW_ROLE_NAME);
        String tenantDomain = eventData.getTenantDomain();

        EnvelopeContext ctx = new EnvelopeContext();

        RoleRef role = enrichRole(new RoleRef(), roleId, tenantDomain);
        if (StringUtils.isNotBlank(newRoleName)) {
            role.setName(newRoleName);
        }

        return new WSO2RoleMetaUpdatedEventPayload.Builder()
                .tenant(ctx.tenant)
                .organization(ctx.organization)
                .initiatorType(ctx.initiatorType)
                .initiatorIpAddress(ctx.initiatorIpAddress)
                .action(ctx.action)
                .role(role)
                .build();
    }

    @Override
    public EventPayload buildRoleDeletedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> props = eventData.getEventParams();
        String roleId = (String) props.get(IdentityEventConstants.EventProperty.ROLE_ID);
        String roleName = (String) props.get(IdentityEventConstants.EventProperty.ROLE_NAME);
        String audience = (String) props.get(IdentityEventConstants.EventProperty.AUDIENCE);
        String audienceId = (String) props.get(IdentityEventConstants.EventProperty.AUDIENCE_ID);
        String audienceName = (String) props.get(IdentityEventConstants.EventProperty.AUDIENCE_NAME);

        EnvelopeContext ctx = new EnvelopeContext();

        RoleRef role = new RoleRef();
        role.setId(roleId);
        role.setName(roleName);
        role.setAudience(buildRoleAudience(audience, audienceId, audienceName));

        return new WSO2RoleDeletedEventPayload.Builder()
                .tenant(ctx.tenant)
                .organization(ctx.organization)
                .initiatorType(ctx.initiatorType)
                .initiatorIpAddress(ctx.initiatorIpAddress)
                .action(ctx.action)
                .role(role)
                .build();
    }

    @Override
    public EventPayload buildRoleUsersUpdatedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> props = eventData.getEventParams();
        String roleId = (String) props.get(IdentityEventConstants.EventProperty.ROLE_ID);
        String tenantDomain = eventData.getTenantDomain();

        EnvelopeContext ctx = new EnvelopeContext();

        WSO2RoleUsersUpdatedEventPayload.RoleWithUsers role =
                enrichRole(new WSO2RoleUsersUpdatedEventPayload.RoleWithUsers(), roleId, tenantDomain);

        List<String> addedUserIds =
                toStringList(props.get(IdentityEventConstants.EventProperty.NEW_USER_ID_LIST));
        List<String> removedUserIds =
                toStringList(props.get(IdentityEventConstants.EventProperty.DELETE_USER_ID_LIST));

        String roleUsersRef = buildRoleRef(roleId, tenantDomain) + "/users";
        final AbstractUserStoreManager userManager = getAbstractUserStoreManager(tenantDomain);

        applyTruncatedList(addedUserIds, ids -> toEnrichedUserEntries(ids, userManager),
                role::setAddedUsers, role::setAddedUsersTruncated,
                role::setAddedUsersTotalCount, role::setAddedUsersRef, roleUsersRef);
        applyTruncatedList(removedUserIds, ids -> toEnrichedUserEntries(ids, userManager),
                role::setRemovedUsers, role::setRemovedUsersTruncated,
                role::setRemovedUsersTotalCount, role::setRemovedUsersRef, roleUsersRef);

        return new WSO2RoleUsersUpdatedEventPayload.Builder()
                .tenant(ctx.tenant)
                .organization(ctx.organization)
                .initiatorType(ctx.initiatorType)
                .initiatorIpAddress(ctx.initiatorIpAddress)
                .action(ctx.action)
                .role(role)
                .build();
    }

    @Override
    public EventPayload buildRoleGroupsUpdatedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> props = eventData.getEventParams();
        String roleId = (String) props.get(IdentityEventConstants.EventProperty.ROLE_ID);
        String tenantDomain = eventData.getTenantDomain();

        EnvelopeContext ctx = new EnvelopeContext();

        WSO2RoleGroupsUpdatedEventPayload.RoleWithGroups role =
                enrichRole(new WSO2RoleGroupsUpdatedEventPayload.RoleWithGroups(), roleId, tenantDomain);

        List<String> addedGroupIds =
                toStringList(props.get(IdentityEventConstants.EventProperty.NEW_GROUP_ID_LIST));
        List<String> removedGroupIds =
                toStringList(props.get(IdentityEventConstants.EventProperty.DELETE_GROUP_ID_LIST));

        String roleRef = buildRoleRef(roleId, tenantDomain);
        final AbstractUserStoreManager userManager = getAbstractUserStoreManager(tenantDomain);

        applyTruncatedList(addedGroupIds, ids -> toEnrichedGroupEntries(ids, userManager),
                role::setAddedGroups, role::setAddedGroupsTruncated,
                role::setAddedGroupsTotalCount, role::setAddedGroupsRef, roleRef);
        applyTruncatedList(removedGroupIds, ids -> toEnrichedGroupEntries(ids, userManager),
                role::setRemovedGroups, role::setRemovedGroupsTruncated,
                role::setRemovedGroupsTotalCount, role::setRemovedGroupsRef, roleRef);

        return new WSO2RoleGroupsUpdatedEventPayload.Builder()
                .tenant(ctx.tenant)
                .organization(ctx.organization)
                .initiatorType(ctx.initiatorType)
                .initiatorIpAddress(ctx.initiatorIpAddress)
                .action(ctx.action)
                .role(role)
                .build();
    }

    @Override
    public EventPayload buildRoleIdpGroupsUpdatedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> props = eventData.getEventParams();
        String roleId = (String) props.get(IdentityEventConstants.EventProperty.ROLE_ID);
        String tenantDomain = eventData.getTenantDomain();

        EnvelopeContext ctx = new EnvelopeContext();

        WSO2RoleIdpGroupsUpdatedEventPayload.RoleWithIdpGroups role =
                enrichRole(new WSO2RoleIdpGroupsUpdatedEventPayload.RoleWithIdpGroups(), roleId, tenantDomain);

        List<IdpGroup> addedIdpGroups = toIdpGroupList(props.get(
                IdentityEventConstants.EventProperty.NEW_GROUP_ID_LIST));
        List<IdpGroup> removedIdpGroups = toIdpGroupList(props.get(
                IdentityEventConstants.EventProperty.DELETE_GROUP_ID_LIST));

        String roleRef = buildRoleRef(roleId, tenantDomain);

        applyTruncatedList(addedIdpGroups, groups -> toEnrichedIdpGroupEntries(groups, tenantDomain),
                role::setAddedIdpGroups, role::setAddedIdpGroupsTruncated,
                role::setAddedIdpGroupsTotalCount, role::setAddedIdpGroupsRef, roleRef);
        applyTruncatedList(removedIdpGroups, groups -> toEnrichedIdpGroupEntries(groups, tenantDomain),
                role::setRemovedIdpGroups, role::setRemovedIdpGroupsTruncated,
                role::setRemovedIdpGroupsTotalCount, role::setRemovedIdpGroupsRef, roleRef);

        return new WSO2RoleIdpGroupsUpdatedEventPayload.Builder()
                .tenant(ctx.tenant)
                .organization(ctx.organization)
                .initiatorType(ctx.initiatorType)
                .initiatorIpAddress(ctx.initiatorIpAddress)
                .action(ctx.action)
                .role(role)
                .build();
    }

    @Override
    public EventPayload buildRolePermissionsUpdatedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> props = eventData.getEventParams();
        String roleId = (String) props.get(IdentityEventConstants.EventProperty.ROLE_ID);
        String tenantDomain = eventData.getTenantDomain();

        EnvelopeContext ctx = new EnvelopeContext();

        WSO2RolePermissionsUpdatedEventPayload.RoleWithPermissions role =
                enrichRole(new WSO2RolePermissionsUpdatedEventPayload.RoleWithPermissions(), roleId, tenantDomain);

        List<String> addedPermissions =
                toPermissionNames(props.get(IdentityEventConstants.EventProperty.ADDED_PERMISSIONS));
        List<String> removedPermissions =
                toPermissionNames(props.get(IdentityEventConstants.EventProperty.DELETED_PERMISSIONS));

        role.setAddedPermissions(addedPermissions.isEmpty() ? null : addedPermissions);
        role.setRemovedPermissions(removedPermissions.isEmpty() ? null : removedPermissions);

        return new WSO2RolePermissionsUpdatedEventPayload.Builder()
                .tenant(ctx.tenant)
                .organization(ctx.organization)
                .initiatorType(ctx.initiatorType)
                .initiatorIpAddress(ctx.initiatorIpAddress)
                .action(ctx.action)
                .role(role)
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    // ---- private helpers ----

    /**
     * Common envelope fields resolved once per event.
     */
    private static class EnvelopeContext {

        final Tenant tenant;
        final Organization organization;
        final String initiatorType;
        final String initiatorIpAddress;
        final String action;

        EnvelopeContext() {

            this.tenant = WSO2PayloadUtils.buildTenant();
            this.organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                    IdentityContext.getThreadLocalIdentityContext());
            Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
            this.initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
            this.initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();
            this.action = WSO2PayloadUtils.getFlowAction(flow);
        }
    }

    /**
     * Populate id / ref / name / audience on the given role block by looking up RoleBasicInfo.
     * Returns the same instance so callers can inline it.
     */
    private <R extends RoleRef> R enrichRole(R role, String roleId, String tenantDomain) {

        role.setId(roleId);
        role.setRef(buildRoleRef(roleId, tenantDomain));
        RoleBasicInfo basicInfo = getRoleBasicInfo(roleId, tenantDomain);
        if (basicInfo != null) {
            role.setName(basicInfo.getName());
            role.setAudience(buildRoleAudience(basicInfo.getAudience(),
                    basicInfo.getAudienceId(), basicInfo.getAudienceName()));
        }
        return role;
    }

    /**
     * Apply the "cap + mark truncated" pattern to an added/removed source list.
     * If the source is empty or null nothing is set; otherwise the mapped entries
     * are stored, and if the source exceeds {@link Constants.RoleManagement#ROLE_LIST_MAX_SIZE}
     * the truncated / totalCount / ref siblings are populated.
     */
    private static <S, T> void applyTruncatedList(List<S> source, Function<List<S>, List<T>> mapper,
                                                  Consumer<List<T>> setValues,
                                                  Consumer<Boolean> setTruncated,
                                                  IntConsumer setTotalCount,
                                                  Consumer<String> setRef, String ref) {

        if (source == null || source.isEmpty()) {
            return;
        }
        if (source.size() > ROLE_LIST_MAX_SIZE) {
            setValues.accept(mapper.apply(source.subList(0, ROLE_LIST_MAX_SIZE)));
            setTruncated.accept(true);
            setTotalCount.accept(source.size());
            setRef.accept(ref);
        } else {
            setValues.accept(mapper.apply(source));
        }
    }

    /**
     * Build the SCIM2 roles ref URL for the given role ID in the current tenant context.
     */
    private String buildRoleRef(String roleId, String tenantDomain) {

        String baseUrl = WSO2PayloadUtils.constructFullURLWithEndpoint(SCIM2_ROLES_ENDPOINT, tenantDomain);
        return (baseUrl != null) ? baseUrl + "/" + roleId : null;
    }

    /**
     * Fetch RoleBasicInfo from the RoleManagementService (cache-backed).
     * Returns null on any error so the caller can proceed without enrichment.
     */
    private RoleBasicInfo getRoleBasicInfo(String roleId, String tenantDomain) {

        if (StringUtils.isBlank(roleId) || StringUtils.isBlank(tenantDomain)) {
            return null;
        }
        RoleManagementService roleManagementService =
                WSO2EventHookHandlerDataHolder.getInstance().getRoleManagementService();
        if (roleManagementService == null) {
            LOG.debug("RoleManagementService is not available. Skipping enrichment for role: " + roleId);
            return null;
        }
        try {
            return roleManagementService.getRoleBasicInfoById(roleId, tenantDomain);
        } catch (IdentityRoleManagementException e) {
            LOG.debug("Could not fetch RoleBasicInfo for role: " + roleId + " in tenant: " + tenantDomain, e);
            return null;
        }
    }

    /**
     * Build a RoleAudience from the audience fields.
     */
    private RoleAudience buildRoleAudience(String audience, String audienceId, String audienceName) {

        if (StringUtils.isBlank(audience)) {
            return null;
        }
        return new RoleAudience(audience, audienceId, audienceName);
    }

    /**
     * Convert a raw object from EventProperties to a List of Strings.
     */
    private List<String> toStringList(Object obj) {

        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            List<String> result = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof String) {
                    result.add((String) item);
                }
            }
            return result;
        }
        return Collections.emptyList();
    }

    /**
     * Extract permission names (the {@code name} field) from a raw list of Permission objects.
     */
    private List<String> toPermissionNames(Object obj) {

        if (!(obj instanceof List)) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>();
        for (Object item : (List<?>) obj) {
            if (item instanceof Permission) {
                String name = ((Permission) item).getName();
                if (name != null) {
                    result.add(name);
                }
            }
        }
        return result;
    }

    /**
     * Convert a raw object from EventProperties to a List of IdpGroup.
     */
    private List<IdpGroup> toIdpGroupList(Object obj) {

        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            List<IdpGroup> result = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof IdpGroup) {
                    result.add((IdpGroup) item);
                }
            }
            return result;
        }
        return Collections.emptyList();
    }

    /**
     * Build user entries carrying id + user-store domain + selected claims (username,
     * agent name). The agent-name claim is emitted only when non-blank; agents are
     * identified uniformly through this claim rather than a separate representation.
     */
    private List<UserEntry> toEnrichedUserEntries(List<String> userIds, AbstractUserStoreManager userManager) {

        List<UserEntry> entries = new ArrayList<>();
        for (String userId : userIds) {
            Map<String, String> claimValues = resolveUserClaims(userId, userManager,
                    new String[]{USERNAME_CLAIM_URI, AGENT_NAME_CLAIM_URI});
            List<UserClaim> claims = new ArrayList<>();
            String username = claimValues.get(USERNAME_CLAIM_URI);
            String userStoreDomain = null;
            if (StringUtils.isNotBlank(username)) {
                // When the username already carries the user-store domain prefix.
                if (StringUtils.contains(username, UserCoreConstants.DOMAIN_SEPARATOR)) {
                    userStoreDomain = UserCoreUtil.extractDomainFromName(username);
                    username = UserCoreUtil.removeDomainFromName(username);
                }
                claims.add(new UserClaim.Builder().uri(USERNAME_CLAIM_URI).value(username).build());
            }
            if (userStoreDomain == null) {
                userStoreDomain = resolveUserStoreDomain(userId, userManager);
            }
            String agentName = claimValues.get(AGENT_NAME_CLAIM_URI);
            if (StringUtils.isNotBlank(agentName)) {
                claims.add(new UserClaim.Builder().uri(AGENT_NAME_CLAIM_URI).value(agentName).build());
            }
            entries.add(new UserEntry(userId, userStoreDomain, claims.isEmpty() ? null : claims));
        }
        return entries;
    }

    /**
     * Resolve the user-store domain that owns the given userId. Returns null on failure.
     */
    private String resolveUserStoreDomain(String userId, AbstractUserStoreManager userManager) {

        if (userManager == null || StringUtils.isBlank(userId)) {
            return null;
        }
        try {
            String domainQualified = userManager.getUserNameFromUserID(userId);
            if (StringUtils.isBlank(domainQualified)) {
                return null;
            }
            return UserCoreUtil.extractDomainFromName(domainQualified);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            LOG.debug("Could not resolve user-store domain for userId: " + userId, e);
            return null;
        }
    }

    /**
     * Fetch the requested claim values for a user by ID. Returns an empty map on any error.
     */
    private Map<String, String> resolveUserClaims(String userId, AbstractUserStoreManager userManager,
                                                  String[] claimUris) {

        if (userManager == null || StringUtils.isBlank(userId) || claimUris == null || claimUris.length == 0) {
            return Collections.emptyMap();
        }
        try {
            Map<String, String> values = userManager.getUserClaimValuesWithID(userId, claimUris, null);
            return values != null ? values : Collections.emptyMap();
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            LOG.debug("Could not resolve claims for userId: " + userId, e);
            return Collections.emptyMap();
        }
    }

    /**
     * Resolve groups for the given group IDs and return enriched entries.
     */
    private List<GroupEntry> toEnrichedGroupEntries(List<String> groupIds, AbstractUserStoreManager userManager) {

        List<GroupEntry> entries = new ArrayList<>();
        for (String groupId : groupIds) {
            Group group = resolveGroupFromGroupId(groupId, userManager);
            if (group == null) {
                entries.add(new GroupEntry(groupId, null, null));
                continue;
            }
            String groupName = group.getGroupName();
            String domain;
            if (StringUtils.contains(groupName, UserCoreConstants.DOMAIN_SEPARATOR)) {
                domain = UserCoreUtil.extractDomainFromName(groupName);
                groupName = UserCoreUtil.removeDomainFromName(groupName);
            } else {
                domain = StringUtils.isNotBlank(group.getUserStoreDomain())
                        ? group.getUserStoreDomain()
                        : UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
            }
            entries.add(new GroupEntry(groupId, groupName, domain));
        }
        return entries;
    }

/**
     * Build IdpGroupEntry list, resolving missing idpName from IdpManager when absent.
     */
    private List<WSO2RoleIdpGroupsUpdatedEventPayload.IdpGroupEntry> toEnrichedIdpGroupEntries(
            List<IdpGroup> idpGroups, String tenantDomain) {

        List<WSO2RoleIdpGroupsUpdatedEventPayload.IdpGroupEntry> entries = new ArrayList<>();
        for (IdpGroup idpGroup : idpGroups) {
            String idpName = idpGroup.getIdpName();
            if (StringUtils.isBlank(idpName) && StringUtils.isNotBlank(idpGroup.getIdpId())) {
                idpName = resolveIdpNameFromIdpId(idpGroup.getIdpId(), tenantDomain);
            }
            entries.add(new WSO2RoleIdpGroupsUpdatedEventPayload.IdpGroupEntry(
                    idpGroup.getGroupId(), idpGroup.getGroupName(),
                    idpGroup.getIdpId(), idpName));
        }
        return entries;
    }

    /**
     * Obtain an AbstractUserStoreManager for the given tenant. Returns null if unavailable.
     */
    private AbstractUserStoreManager getAbstractUserStoreManager(String tenantDomain) {

        RealmService realmService = WSO2EventHookHandlerDataHolder.getInstance().getRealmService();
        if (realmService == null) {
            LOG.debug("RealmService unavailable; skipping username/groupName enrichment.");
            return null;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserRealm realm = realmService.getTenantUserRealm(tenantId);
            if (realm == null) {
                return null;
            }
            org.wso2.carbon.user.api.UserStoreManager userManager = realm.getUserStoreManager();
            if (userManager instanceof AbstractUserStoreManager) {
                return (AbstractUserStoreManager) userManager;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            LOG.debug("Could not obtain UserStoreManager for tenant: " + tenantDomain, e);
        }
        return null;
    }

/**
     * Fetch the {@link Group} for the given groupId. Returns null on failure or when
     * the resolved group has no name.
     */
    private Group resolveGroupFromGroupId(String groupId, AbstractUserStoreManager userManager) {

        if (userManager == null || StringUtils.isBlank(groupId)) {
            return null;
        }
        try {
            Group group = userManager.getGroup(groupId, null);
            if (group == null || StringUtils.isBlank(group.getGroupName())) {
                return null;
            }
            return group;
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            LOG.debug("Could not resolve group for groupId: " + groupId, e);
            return null;
        }
    }

    /**
     * Resolve IdP display name from idpId (resource ID) via IdpManager. Returns null on failure.
     */
    private String resolveIdpNameFromIdpId(String idpId, String tenantDomain) {

        IdpManager idpManager = WSO2EventHookHandlerDataHolder.getInstance().getIdpManager();
        if (idpManager == null) {
            LOG.debug("IdpManager unavailable; skipping idpName enrichment for idpId: " + idpId);
            return null;
        }
        try {
            IdentityProvider idp = idpManager.getIdPByResourceId(idpId, tenantDomain, true);
            return idp != null ? idp.getIdentityProviderName() : null;
        } catch (IdentityProviderManagementException e) {
            LOG.debug("Could not resolve IdP name for idpId: " + idpId + " in tenant: " + tenantDomain, e);
            return null;
        }
    }
}
