/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.UserSharingEvent;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserAccountEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserGroupUpdateEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserSharingEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Group;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.TargetOrganization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.PRE_DELETE_USER_ID;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.ORGANIZATIONS_API_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;

/**
 * WSO2 UserOperation Event Payload Builder.
 */
public class WSO2UserOperationEventPayloadBuilder implements UserOperationEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2UserOperationEventPayloadBuilder.class);
    private static final String USER_SHARE_ACTION = "USER_SHARE";
    private static final String USER_UNSHARE_ACTION = "USER_UNSHARE";

    @Override
    public EventPayload buildUserGroupUpdateEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());

        // todo: should remove retrieving user store manager as a property.
        //  Rather load user store managed from realm service.
        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration()
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        Group group = buildGroup(properties, userStoreManager, accessedTenantDomain);
        UserStore userStore = new UserStore(userStoreDomainName);

        Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = null;
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
        }
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());

        return new WSO2UserGroupUpdateEventPayload.Builder()
                .initiatorType(initiatorType)
                .group(group)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public EventPayload buildUserDeleteEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration()
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        UserStore userStore = new UserStore(userStoreDomainName);

        List<UserClaim> userClaims = new ArrayList<>();

        String userName =
                String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.USER_NAME));
        Optional<UserClaim> userNameOptional =
                WSO2PayloadUtils.generateUserClaim(FrameworkConstants.USERNAME_CLAIM, userName,
                        accessedTenantDomain);
        userNameOptional.ifPresent(userClaims::add);

        if (eventData.getEventParams().get("EMAIL_ADDRESS") != null) {
            String emailAddress = String.valueOf(eventData.getEventParams().get("EMAIL_ADDRESS"));
            Optional<UserClaim> emailAddressOptional =
                    WSO2PayloadUtils.generateUserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress,
                            accessedTenantDomain);
            emailAddressOptional.ifPresent(userClaims::add);
        }

        String userId;

        try {
            userId = String.valueOf(IdentityUtil.threadLocalProperties.get().get(PRE_DELETE_USER_ID));

            User deletedUser = new User();
            deletedUser.setId(userId);
            deletedUser.setRef(WSO2PayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT,
                    accessedTenantDomain) + "/" + userId);
            deletedUser.setClaims(userClaims);

            Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);

            Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                    IdentityContext.getThreadLocalIdentityContext());
            deletedUser.setOrganization(organization);

            Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
            String action = WSO2PayloadUtils.getFlowAction(flow);
            String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
            String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

            return new WSO2UserAccountEventPayload.Builder()
                    .initiatorType(initiatorType)
                    .action(action)
                    .user(deletedUser)
                    .tenant(tenant)
                    .organization(organization)
                    .userStore(userStore)
                    .initiatorIpAddress(initiatorIpAddress)
                    .build();
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(PRE_DELETE_USER_ID);
        }
    }

    @Override
    public EventPayload buildUserUnlockAccountEvent(EventData eventData) throws IdentityEventException {

        return this.buildUserAccountEvent(eventData);
    }

    private EventPayload buildUserAccountEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration()
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        UserStore userStore = new UserStore(userStoreDomainName);

        String userName =
                String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.USER_NAME));
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());

        User user = new User();
        enrichUser(userStoreManager, userName, user,
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());
        user.setRef(WSO2PayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT, accessedTenantDomain)
                + "/" + user.getId());

        Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        user.setOrganization(organization);

        return new WSO2UserAccountEventPayload.Builder()
                .initiatorType(initiatorType)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    private EventPayload buildUserEnableEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());

        String userStoreDomainName =
                String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));
        UserStore userStore = new UserStore(userStoreDomainName);

        String userId = String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.USER_ID));
        User user = new User();
        user.setId(userId);

        AbstractUserStoreManager userStoreManager = null;
        Object userStoreManagerObj = properties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        if (userStoreManagerObj instanceof AbstractUserStoreManager) {
            userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        }
        String userName =
                String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.USER_NAME));
        enrichUser(userStoreManager, userName, user, accessedTenantDomain);

        user.setRef(WSO2PayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT, accessedTenantDomain)
                + "/" + user.getId());

        Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        user.setOrganization(organization);

        return new WSO2UserAccountEventPayload.Builder()
                .initiatorType(initiatorType)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .action(action)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public EventPayload buildUserLockAccountEvent(EventData eventData) throws IdentityEventException {

        return this.buildUserAccountEvent(eventData);
    }

    @Override
    public EventPayload buildUserProfileUpdateEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());
        String userStoreDomainName =
                String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));
        String userId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_ID));

        UserStore userStore = new UserStore(userStoreDomainName);

        List<UserClaim> addedClaims =
                populateClaims(properties, IdentityEventConstants.EventProperty.USER_CLAIMS_ADDED,
                        accessedTenantDomain);
        List<UserClaim> modifiedClaims =
                populateClaims(properties, IdentityEventConstants.EventProperty.USER_CLAIMS_MODIFIED,
                        accessedTenantDomain);
        List<UserClaim> deletedClaims =
                populateClaims(properties, IdentityEventConstants.EventProperty.USER_CLAIMS_DELETED,
                        accessedTenantDomain);
        List<UserClaim> additionalClaims = populateClaims(properties, "ADDITIONAL_USER_CLAIMS", accessedTenantDomain);

        User user = new User();
        user.setId(userId);
        user.setRef(WSO2PayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT, accessedTenantDomain)
                + "/" + user.getId());
        user.setAdditionalClaims(additionalClaims);
        user.setAddedClaims(addedClaims);
        user.setUpdatedClaims(modifiedClaims);
        user.setRemovedClaims(deletedClaims);

        Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();
        String action = null;
        if (flow != null) {
            action = Optional.ofNullable(resolveAction(flow.getName()))
                    .map(Enum::name)
                    .orElse(null);
        }
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        user.setOrganization(organization);

        return new WSO2UserAccountEventPayload.Builder()
                .initiatorType(initiatorType)
                .action(action)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public EventPayload buildUserAccountEnableEvent(EventData eventData) throws IdentityEventException {

        return this.buildUserEnableEvent(eventData);
    }

    @Override
    public EventPayload buildUserAccountDisableEvent(EventData eventData) throws IdentityEventException {

        return this.buildUserEnableEvent(eventData);
    }

    @Override
    public EventPayload buildUserCreatedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());

        String userStoreDomainName = WSO2PayloadUtils.resolveUserStoreDomain(properties);
        UserStore userStore = new UserStore(userStoreDomainName);

        User newUser = new User();
        WSO2PayloadUtils.enrichUser(properties, newUser, accessedTenantDomain);

        if (StringUtils.isBlank(newUser.getId())) {

            String userName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_NAME));
            // User set password flow for email invitation by admin.
            newUser = WSO2PayloadUtils.buildUser(userStoreDomainName, userName, accessedTenantDomain);
        }

        Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();
        String action = null;
        if (flow != null) {
            action = Optional.ofNullable(resolveAction(flow.getName()))
                    .map(Enum::name)
                    .orElse(null);
        }
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        newUser.setOrganization(organization);

        return new WSO2UserCreatedEventPayload.Builder()
                .initiatorType(initiatorType)
                .action(action)
                .user(newUser)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    private List<UserClaim> populateClaims(Map<String, Object> properties, String userClaimKey, String tenantDomain) {

        if (properties != null && properties.get(userClaimKey) instanceof Map) {

            Map<String, String> userClaimsMap = (Map<String, String>) properties.get(userClaimKey);
            List<UserClaim> userClaims = new ArrayList<>();

            for (Map.Entry<String, String> entry : userClaimsMap.entrySet()) {
                Optional<UserClaim> userClaimOptional =
                        WSO2PayloadUtils.generateUserClaim(entry.getKey(), entry.getValue(), tenantDomain);
                userClaimOptional.ifPresent(userClaims::add);
            }
            return userClaims;
        }
        return null;
    }

    private List<User> buildUserList(AbstractUserStoreManager userStoreManager, Map<String, Object> properties,
                                     String userListPropertyName, String tenantDomain) throws IdentityEventException {

        List<User> users = new ArrayList<>();

        String[] domainQualifiedUsernames = (String[]) properties.get(userListPropertyName);
        if (domainQualifiedUsernames != null) {
            for (String domainQualifiedUsername : domainQualifiedUsernames) {
                User user = new User();
                enrichUser(userStoreManager, domainQualifiedUsername, user, tenantDomain);
                users.add(user);
            }
        }
        return users;
    }

    private static void enrichUser(UserStoreManager userStoreManager, String domainQualifiedUserName, User user,
                                   String tenantDomain)
            throws IdentityEventException {

        String userId;
        try {
            if (StringUtils.isEmpty(user.getId())) {
                userId = userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.USER_ID_CLAIM,
                        UserCoreConstants.DEFAULT_PROFILE);
                user.setId(userId);
            }

            String emailAddress =
                    userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                            UserCoreConstants.DEFAULT_PROFILE);
            Optional<UserClaim> emailAddressUserOptional =
                    WSO2PayloadUtils.generateUserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress,
                            tenantDomain);
            emailAddressUserOptional.ifPresent(user::addClaim);
        } catch (UserStoreException e) {
            throw new IdentityEventException(
                    "Error while extracting user claims for the user : " + domainQualifiedUserName, e);
        }
    }

    @Override
    public EventPayload buildUserSharedEvent(EventData eventData) throws IdentityEventException {

        return buildUserSharingEvent(eventData, USER_SHARE_ACTION);
    }

    @Override
    public EventPayload buildUserUnsharedEvent(EventData eventData) throws IdentityEventException {

        return buildUserSharingEvent(eventData, USER_UNSHARE_ACTION);
    }

    /**
     * Build the payload of a user shared with, or unshared from, an organization. The event is raised in the
     * organization that performed the operation, which may differ from both the organization the user resides in
     * and the organization the user was shared with, so each of them is resolved from the event properties rather
     * than from the thread. Sharing runs asynchronously, where the identity context of the request is not available.
     */
    private EventPayload buildUserSharingEvent(EventData eventData, String action) {

        Map<String, Object> properties = eventData.getEventParams();
        String initiatingTenantDomain = eventData.getTenantDomain();
        String residentOrgId = getStringProperty(properties, UserSharingEvent.ASSOCIATED_ORGANIZATION_ID);
        String targetOrgId = getStringProperty(properties, UserSharingEvent.SHARED_ORGANIZATION_ID);
        String residentTenantDomain = resolveTenantDomainOfOrganization(residentOrgId);
        String targetTenantDomain = resolveTenantDomainOfOrganization(targetOrgId);

        User user = new User();
        String userId = getStringProperty(properties, UserSharingEvent.ASSOCIATED_USER_ID);
        user.setId(userId);
        String userName = getStringProperty(properties, IdentityEventConstants.EventProperty.USER_NAME);
        if (userName != null) {
            List<UserClaim> claims = new ArrayList<>();
            WSO2PayloadUtils.generateUserClaim(FrameworkConstants.USERNAME_CLAIM, userName, residentTenantDomain)
                    .ifPresent(claims::add);
            user.setClaims(claims);
        }
        user.setOrganization(WSO2PayloadUtils.buildOrganizationFromOrgId(residentOrgId, residentTenantDomain));
        user.setRef(buildUserRef(residentTenantDomain, userId));

        User sharedUser = new User();
        String sharedUserId = getStringProperty(properties, UserSharingEvent.SHARED_USER_ID);
        sharedUser.setId(sharedUserId);
        sharedUser.setRef(buildUserRef(targetTenantDomain, sharedUserId));

        Organization targetOrganization =
                WSO2PayloadUtils.buildOrganizationFromOrgId(targetOrgId, targetTenantDomain);
        TargetOrganization.Builder targetOrganizationBuilder = new TargetOrganization.Builder().id(targetOrgId);
        if (targetOrganization != null) {
            targetOrganizationBuilder.name(targetOrganization.getName())
                    .orgHandle(targetOrganization.getOrgHandle())
                    .depth(targetOrganization.getDepth());
        }
        if (targetOrgId != null && initiatingTenantDomain != null) {
            targetOrganizationBuilder.ref(WSO2PayloadUtils.constructFullURLWithEndpoint(ORGANIZATIONS_API_ENDPOINT,
                    initiatingTenantDomain) + "/" + targetOrgId);
        }

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        return new WSO2UserSharingEventPayload.Builder()
                .initiatorType(WSO2PayloadUtils.getFlowInitiatorType(flow))
                .initiatorIpAddress(WSO2PayloadUtils.resolveInitiatorIpAddress())
                .action(action)
                .tenant(resolveRootTenant(initiatingTenantDomain))
                .organization(WSO2PayloadUtils.buildOrganizationFromTenantDomain(initiatingTenantDomain))
                .user(user)
                .targetOrganization(targetOrganizationBuilder.build())
                .sharedUser(sharedUser)
                .sharedType(getStringProperty(properties, UserSharingEvent.SHARED_TYPE))
                .build();
    }

    private String getStringProperty(Map<String, Object> properties, String key) {

        Object value = properties != null ? properties.get(key) : null;
        return value != null ? String.valueOf(value) : null;
    }

    private String resolveTenantDomainOfOrganization(String organizationId) {

        if (organizationId == null) {
            return null;
        }
        try {
            return WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(organizationId);
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving the tenant of organization: " + organizationId, e);
            return null;
        }
    }

    private String buildUserRef(String tenantDomain, String userId) {

        if (tenantDomain == null || userId == null) {
            return null;
        }
        return WSO2PayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT, tenantDomain) + "/" + userId;
    }

    /**
     * Resolve the root tenant of the organization the event was raised in. The identity context carries it for a
     * request, but not for the asynchronous sharing flow.
     */
    private Tenant resolveRootTenant(String tenantDomain) {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        if (tenant != null || tenantDomain == null) {
            return tenant;
        }
        try {
            OrganizationManager organizationManager =
                    WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager();
            String organizationId = organizationManager.resolveOrganizationId(tenantDomain);
            String rootTenantDomain = organizationManager.resolveTenantDomain(
                    organizationManager.getPrimaryOrganizationId(organizationId));
            return new Tenant(String.valueOf(IdentityTenantUtil.getTenantId(rootTenantDomain)), rootTenantDomain);
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving the root tenant of: " + tenantDomain, e);
            return null;
        }
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    private Group buildGroup(Map<String, Object> properties, AbstractUserStoreManager userStoreManager,
                             String tenantDomain)
            throws IdentityEventException {

        String groupName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.ROLE_NAME));
        org.wso2.carbon.user.core.common.Group groupFromUserStore;
        try {
            groupFromUserStore = userStoreManager.getGroupByGroupName(groupName, null);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new IdentityEventException("Error while extracting group Id for the group Name: " + groupName, e);
        }
        String groupId = groupFromUserStore.getGroupID();
        String groupLocation = groupFromUserStore.getLocation();

        List<User> deletedUsers =
                buildUserList(userStoreManager, properties, IdentityEventConstants.EventProperty.DELETED_USERS,
                        tenantDomain);
        List<User> addedUsers =
                buildUserList(userStoreManager, properties, IdentityEventConstants.EventProperty.NEW_USERS,
                        tenantDomain);

        Group group = new Group();
        group.setName(groupName);
        group.setRef(groupLocation);
        group.setId(groupId);
        group.setRemovedUsers(deletedUsers);
        group.setAddedUsers(addedUsers);

        return group;
    }

    private UserOperationAction resolveAction(Flow.Name name) {

        if (name == null) {
            return null;
        }

        switch (name) {
            case PROFILE_UPDATE:
                return UserOperationAction.PROFILE_UPDATE;
            case INVITE:
            case INVITED_USER_REGISTRATION:
                return UserOperationAction.INVITE;
            case REGISTER:
                return UserOperationAction.REGISTER;
            case JUST_IN_TIME_PROVISION:
                return UserOperationAction.JUST_IN_TIME_PROVISION;
            default: {
                return null;
            }
        }
    }

    public enum UserOperationAction {
        INVITE, PROFILE_UPDATE, REGISTER, JUST_IN_TIME_PROVISION
    }
}
