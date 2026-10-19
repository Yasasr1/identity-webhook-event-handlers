/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.wso2.event.handler.internal.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.core.context.util.IdentityContextUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.SharedUserProfile;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.user.core.constants.UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.CREATED_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.EMAIL_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.LOCATION_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.MODIFIED_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.RESOURCE_TYPE_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.USERNAME_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.WSO2_CLAIM_URI_PREFIX;

public class WSO2PayloadUtils {

    private static final Log log = LogFactory.getLog(WSO2PayloadUtils.class);

    /**
     * Root tenant domain of a tenant, by tenant domain. A tenant's place in the organization hierarchy does not
     * change for its lifetime, and this is read once per resource reference, so it is resolved once and kept.
     */
    private static final Map<String, String> ROOT_TENANT_DOMAINS = new ConcurrentHashMap<>();

    /**
     * Organization owning an application, by application resource identifier. An application does not move
     * between organizations, so this is resolved once and kept.
     */
    private static final Map<String, Organization> APPLICATION_ORGANIZATIONS = new ConcurrentHashMap<>();

    // Generic user based grant types that are typically associated with a user.
    private static final Set<String> USER_BASED_GRANT_TYPES = Set.of(
            "authorization_code",
            "implicit",
            "password",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:saml2-bearer",
            "urn:ietf:params:oauth:grant-type:jwt-bearer");

    public static void populateUserClaims(User user, AuthenticatedUser authenticatedUser, String tenantDomain) {

        if (authenticatedUser == null) {
            return;
        }

        Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();
        if (userAttributes != null) {
            userAttributes.forEach((claimMapping, claimValue) -> {
                if (isValidClaim(claimMapping, claimValue)) {
                    String claimUri = claimMapping.getLocalClaim().getClaimUri();
                    handleClaim(user, claimUri, claimValue, tenantDomain);
                }
            });
        }

        if (shouldAddUsernameClaim(user, authenticatedUser)) {
            Optional<UserClaim> userNameClaimOptional = generateUserClaim(
                    USERNAME_CLAIM, authenticatedUser.getUserName(), authenticatedUser.getTenantDomain());
            userNameClaimOptional.ifPresent(user::addClaim);
        }

        if (authenticatedUser.isSharedUser()) {
            String sharedUserTenantDomain = null;
            try {
                sharedUserTenantDomain = WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(authenticatedUser.getAccessingOrganization());
            } catch (OrganizationManagementException e) {
                log.warn(e.getMessage(), e);
            }
            String sharedUserRef = constructFullURLWithEndpoint(Constants.SCIM2_USERS_ENDPOINT,
                    sharedUserTenantDomain) + "/" + authenticatedUser.getSharedUserId();
            SharedUserProfile sharedUserProfile = new SharedUserProfile(authenticatedUser.getSharedUserId(),
                    sharedUserRef);
            user.setSharedUserProfile(sharedUserProfile);
        }
    }

    private static boolean isValidClaim(ClaimMapping claimMapping, String claimValue) {

        return claimMapping != null &&
                claimMapping.getLocalClaim() != null &&
                StringUtils.isNotBlank(claimMapping.getLocalClaim().getClaimUri()) &&
                StringUtils.isNotBlank(claimValue) &&
                claimMapping.getLocalClaim().getClaimUri().startsWith(WSO2_CLAIM_URI_PREFIX);
    }

    private static boolean shouldAddUsernameClaim(User user, AuthenticatedUser authenticatedUser) {

        return StringUtils.isNotBlank(authenticatedUser.getUserName()) &&
                (user.getClaims() == null ||
                        user.getClaims().stream().noneMatch(claim -> USERNAME_CLAIM_URI.equals(claim.getUri())));
    }

    public static void populateUserClaims(User user, String userId, String tenantDomain) {

        UserStoreManager userStoreManager = getUserStoreManagerByTenantDomain(tenantDomain);
        if (!(userStoreManager instanceof UniqueIDUserStoreManager)) {
            return;
        }

        Map<String, String> claimValues;
        try {
            claimValues = ((UniqueIDUserStoreManager) userStoreManager).getUserClaimValuesWithID(
                    userId, new String[] {USERNAME_CLAIM_URI, EMAIL_CLAIM_URI}, null);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            String nonExistingUserErrorCode = ERROR_CODE_NON_EXISTING_USER.getCode();
            // Older user store managers carry the error code only as a prefix of the message.
            if (nonExistingUserErrorCode.equals(e.getErrorCode()) ||
                    (e.getMessage() != null && e.getMessage().startsWith(nonExistingUserErrorCode))) {
                if (log.isDebugEnabled()) {
                    log.debug("User with ID: " + userId + " does not exist in tenant: " + tenantDomain);
                }
            } else {
                log.error("Error while retrieving user claims for user: " + userId + " in tenant: " + tenantDomain, e);
            }
            return;
        }

        if (claimValues == null || claimValues.isEmpty()) {
            return;
        }

        claimValues.forEach((claimUri, claimValue) -> {
            if (isValidClaim(claimUri, claimValue)) {
                handleClaim(user, claimUri, claimValue, tenantDomain);
            }
        });
    }

    private static boolean isValidClaim(String claimUri, String claimValue) {

        return StringUtils.isNotBlank(claimUri) &&
                StringUtils.isNotBlank(claimValue) &&
                claimUri.startsWith(WSO2_CLAIM_URI_PREFIX);
    }

    public static void populateUserIdAndRef(User user, String userId) {

        populateUserIdAndRef(user, userId, null);
    }

    /**
     * Set the user's identifier and the reference to it.
     *
     * @param user         User to populate.
     * @param userId       Identifier of the user.
     * @param tenantDomain Tenant the user resides in, which decides whether the reference is addressed through the
     *                     organization perspective. Null falls back to the organization on the thread.
     */
    public static void populateUserIdAndRef(User user, String userId, String tenantDomain) {

        user.setId(userId);
        user.setRef(constructFullURLWithEndpoint(Constants.SCIM2_USERS_ENDPOINT, tenantDomain) + "/" + userId);
    }

    private static void handleClaim(User user, String claimUri, String claimValue, String tenantDomain) {

        switch (claimUri) {
            case Constants.GROUPS_CLAIM:
                user.addGroup(claimValue);
                break;
            case Constants.MULTI_ATTRIBUTE_SEPARATOR:
            case Constants.IDENTITY_PROVIDER_MAPPED_USER_ROLES:
            case Constants.USER_ORGANIZATION:
                // Skip these claims
                break;
            default:
                Optional<UserClaim> userClaimOptional = generateUserClaim(claimUri, claimValue, tenantDomain);
                userClaimOptional.ifPresent(user::addClaim);
                break;
        }
    }

    public static void populateUserIdAndRef(User user, AuthenticatedUser authenticatedUser) {

        try {
            user.setId(authenticatedUser.getUserId());
            if (!authenticatedUser.isSharedUser()) {
                // The authenticated user carries the tenant it resides in, which is the organization the reference
                // has to be addressed through.
                user.setRef(constructFullURLWithEndpoint(Constants.SCIM2_USERS_ENDPOINT,
                        authenticatedUser.getTenantDomain()) + "/" + authenticatedUser.getUserId());
            }
        } catch (UserIdNotFoundException e) {
            //TODO: Need to verify when this exception is thrown and handle it accordingly
            log.debug("Error while resolving user id.", e);
        }
    }

    public static void populateUserIdAndRef(User user, AuthenticatedUser authenticatedUser, String tenantDomain) {

        try {
            user.setId(authenticatedUser.getUserId());
            if (!authenticatedUser.isSharedUser()) {
                // The authenticated user carries the tenant it resides in, which is the organization the reference
                // has to be addressed through.
                user.setRef(constructFullURLWithEndpoint(Constants.SCIM2_USERS_ENDPOINT, tenantDomain) + "/" +
                        authenticatedUser.getUserId());
            }
        } catch (UserIdNotFoundException e) {
            //TODO: Need to verify when this exception is thrown and handle it accordingly
            log.debug("Error while resolving user id.", e);
        }
    }

    /**
     * Retrieves the UserStoreManager for the given tenant domain.
     *
     * @param tenantDomain The tenant domain.
     * @return The UserStoreManager for the specified tenant domain, or null if not found.
     */
    private static UserStoreManager getUserStoreManagerByTenantDomain(String tenantDomain) {

        try {
            UserRealm userRealm = getUserRealm(tenantDomain);
            if (userRealm == null) {
                return null;
            }

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            if (userStoreManager == null) {
                if (log.isDebugEnabled()) {
                    log.debug("UserStoreManager is null for tenant: " + tenantDomain);
                }
                return null;
            }
            return userStoreManager;

        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while retrieving user store manager for tenant: " +
                        tenantDomain + ". Error: " + e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * Retrieves the RealmConfiguration for the given tenant domain.
     *
     * @param tenantDomain The tenant domain.
     * @return The RealmConfiguration for the specified tenant domain, or null if not found.
     */
    public static RealmConfiguration getRealmConfigurationByTenantDomain(String tenantDomain) {

        try {
            UserRealm userRealm = getUserRealm(tenantDomain);
            if (userRealm == null) {
                return null;
            }

            return userRealm.getRealmConfiguration();

        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while retrieving user store manager for tenant: " +
                        tenantDomain + ". Error: " + e.getMessage(), e);
            }
        }

        return null;
    }

    private static UserRealm getUserRealm(String tenantDomain) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = WSO2EventHookHandlerDataHolder.getInstance().getRealmService();

        if (realmService == null) {
            if (log.isDebugEnabled()) {
                log.debug("RealmService is not available. Skipping setting user store manager.");
            }
            return null;
        }

        UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
        if (userRealm == null) {
            if (log.isDebugEnabled()) {
                log.debug("UserRealm is null for tenant: " + tenantId);
            }
            return null;
        }
        return userRealm;
    }

    public static Optional<UserClaim> generateUserClaim(String claimKey, String claimValue, String tenantDomain) {

        if (StringUtils.isBlank(claimKey) || claimValue == null) {
            return Optional.empty();
        }

        UserClaim.Builder userClaimBuilder = new UserClaim.Builder().uri(claimKey);

        // todo: if the expectation of this method is to build the user name claim for the request payload,
        //  handling multi attribute values is redundant.

        String multiAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();
        if (multiAttributeSeparator == null) {
            multiAttributeSeparator = ","; // default fallback
        }

        if (isMultiValuedClaim(claimKey, tenantDomain)) {
            userClaimBuilder.value(StringUtils.isBlank(claimValue) ? new String[] {} :
                    claimValue.split(Pattern.quote(multiAttributeSeparator)));
        } else {
            userClaimBuilder.value(claimValue);
        }

        return Optional.of(userClaimBuilder.build());
    }

    private static boolean isMultiValuedClaim(String claimUri, String tenantDomain) {

        ClaimMetadataManagementService claimMetadataManagementService =
                WSO2EventHookHandlerDataHolder.getInstance().getClaimMetadataManagementService();

        try {
            Optional<LocalClaim>
                    localClaim = claimMetadataManagementService.getLocalClaim(claimUri, tenantDomain);

            if (localClaim.isPresent()) {
                return Boolean.parseBoolean(localClaim.get().getClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY));
            }

        } catch (ClaimMetadataException e) {
            log.error("Error while retrieving claim metadata for claim URI: " + claimUri, e);
        }
        return false;
    }

    public static void enrichUser(UserStoreManager userStoreManager, String domainQualifiedUserName, User user,
                                  String tenantDomain)
            throws IdentityEventException {

        String userId;
        try {
            userId = userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.USER_ID_CLAIM,
                    UserCoreConstants.DEFAULT_PROFILE);
            user.setId(userId);

            String emailAddress =
                    userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                            UserCoreConstants.DEFAULT_PROFILE);
            Optional<UserClaim> emailAddressUserClaimOptional =
                    generateUserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress,
                            tenantDomain);
            emailAddressUserClaimOptional.ifPresent(user::addClaim);
        } catch (UserStoreException e) {
            throw new IdentityEventException(
                    "Error while extracting user claims for the user : " + domainQualifiedUserName, e);
        }
    }

    public static User buildUser(String userStoreDomain, String userName, String tenantDomain)
            throws IdentityEventException {

        UserStoreManager userStoreManager = getUserStoreManagerByTenantDomain(tenantDomain);
        User user = new User();
        if (userStoreManager != null) {
            String domainQualifiedUserName = userStoreDomain + "/" + userName;
            WSO2PayloadUtils.enrichUser(userStoreManager, domainQualifiedUserName, user, tenantDomain);
            user.setRef(constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT, tenantDomain) + "/" + user.getId());
        }
        return user;
    }

    public static String resolveUserStoreDomain(Map<String, Object> properties) {

        String userStoreDomainName = null;
        if (properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN) != null) {
            userStoreDomainName =
                    String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));
        }
        if (StringUtils.isBlank(userStoreDomainName) &&
                properties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER) != null) {

            Object userStoreManagerObj = properties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
            if (userStoreManagerObj instanceof AbstractUserStoreManager) {
                AbstractUserStoreManager userStoreManager =
                        (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);

                userStoreDomainName = userStoreManager.getRealmConfiguration()
                        .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
            }
        }
        return userStoreDomainName;
    }

    public static List<UserClaim> filterUserClaimsForUserAdd(Map<String, String> userClaims, String tenantDomain) {

        List<UserClaim> userClaimList = new ArrayList<>();
        List<String> excludedClaims = Arrays.asList(
                CREATED_CLAIM,
                MODIFIED_CLAIM,
                RESOURCE_TYPE_CLAIM,
                LOCATION_CLAIM,
                FrameworkConstants.USER_ID_CLAIM);

        for (String userClaimUri : userClaims.keySet()) {
            if (!excludedClaims.contains(userClaimUri)) {
                Optional<UserClaim> userClaimOptional = generateUserClaim(userClaimUri, userClaims.get(userClaimUri),
                        tenantDomain);
                userClaimOptional.ifPresent(userClaimList::add);
            }
        }
        return userClaimList;
    }

    public static void enrichUser(Map<String, Object> properties, User user, String tenantDomain) {

        if (properties.containsKey(IdentityEventConstants.EventProperty.USER_CLAIMS)) {
            Map<String, String> claims = (Map<String, String>) properties.get(IdentityEventConstants.EventProperty
                    .USER_CLAIMS);

            if (claims.containsKey(FrameworkConstants.USER_ID_CLAIM)) {
                user.setId(claims.get(FrameworkConstants.USER_ID_CLAIM));
                user.setRef(constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT, tenantDomain) + "/" + user.getId());
            } else if (claims.containsKey(LOCATION_CLAIM)) {
                user.setRef(claims.get(LOCATION_CLAIM));
                // If the user ID is not set, try to extract it from the ref.
                if (StringUtils.isNotBlank(user.getRef())) {
                    String[] refParts = user.getRef().split("/");
                    if (refParts.length > 0) {
                        user.setId(refParts[refParts.length - 1]);
                    }
                }
            }

            List<UserClaim> filteredUserClaims = filterUserClaimsForUserAdd(claims, tenantDomain);
            user.setClaims(filteredUserClaims);
        }
    }

    public static String constructFullURLWithEndpoint(String endpoint) {

        return constructFullURLWithEndpoint(endpoint, null);
    }

    /**
     * Full URL of an endpoint, addressed the way the tenant holding the resource is addressed.
     *
     * @param endpoint             Endpoint of the resource, such as /scim2/Users.
     * @param resourceTenantDomain Tenant the resource resides in. Null falls back to the organization on the
     *                             thread, which is the tenant the operation was performed in.
     * @return Full URL of the endpoint.
     */
    public static String constructFullURLWithEndpoint(String endpoint, String resourceTenantDomain) {

        if (endpoint == null) {
            throw new IllegalArgumentException("Endpoint cannot be null.");
        }
        return constructBaseURL(resourceTenantDomain) + endpoint;
    }

    public static Organization buildOrganizationFromIdentityContext(IdentityContext identityContext) {

        if (identityContext.getOrganization() != null) {
            return new Organization(
                    identityContext.getOrganization().getId(),
                    identityContext.getOrganization().getName(),
                    identityContext.getOrganization().getOrganizationHandle(),
                    identityContext.getOrganization().getDepth()
            );
        }
        return null;
    }

    /**
     * Organization owning the application a session was established against.
     * <p>
     * Only a session of a sub organization carries this: in a root organization the application and the session
     * belong to the same organization, and naming it adds nothing.
     * <p>
     * An application reached from a sub organization is either shared from an ancestor, in which case it is owned
     * by the organization the main application resides in, or created in the organization itself, in which case
     * it is owned by that organization. Which of the two it is, is what the main application lookup answers: it
     * resolves for a shared application and returns nothing for an application of the organization's own.
     *
     * @param applicationResourceId Resource identifier of the application as the session records it.
     * @param sessionTenantDomain   Tenant the session belongs to.
     * @return The owning organization, or null for a session of a root organization or when it cannot be
     * resolved.
     */
    public static Organization resolveApplicationOrganization(String applicationResourceId,
                                                              String sessionTenantDomain) {

        if (StringUtils.isBlank(applicationResourceId) || StringUtils.isBlank(sessionTenantDomain) ||
                !isOrganization(sessionTenantDomain)) {
            return null;
        }
        Organization cachedOrganization = APPLICATION_ORGANIZATIONS.get(applicationResourceId);
        if (cachedOrganization != null) {
            return cachedOrganization;
        }
        Organization organization = resolveOwningOrganization(applicationResourceId, sessionTenantDomain);
        if (organization != null) {
            APPLICATION_ORGANIZATIONS.put(applicationResourceId, organization);
        }
        return organization;
    }

    private static Organization resolveOwningOrganization(String applicationResourceId, String sessionTenantDomain) {

        try {
            ApplicationManagementService applicationManagementService =
                    WSO2EventHookHandlerDataHolder.getInstance().getApplicationManagementService();
            if (applicationManagementService == null) {
                return null;
            }
            String mainApplicationId = applicationManagementService.getMainAppId(applicationResourceId);
            if (StringUtils.isBlank(mainApplicationId)) {
                // Not shared from an ancestor, so the application belongs to the organization of the session.
                return buildOrganizationFromTenantDomain(sessionTenantDomain);
            }
            String owningTenantDomain = IdentityTenantUtil.getTenantDomain(
                    applicationManagementService.getTenantIdByApp(mainApplicationId));
            return buildOrganizationFromTenantDomain(owningTenantDomain);
        } catch (IdentityApplicationManagementException e) {
            log.debug("Error while resolving the organization owning application: " + applicationResourceId, e);
            return null;
        }
    }

    /**
     * Organization owning the application an event was raised against, given the application's own tenant.
     * <p>
     * Only an event of a sub organization carries this: in a root organization the application and the event
     * belong to the same organization, and naming it adds nothing.
     *
     * @param applicationTenantDomain Tenant the application resides in.
     * @param eventTenantDomain       Tenant the event belongs to.
     * @return The organization owning the application, or null for an event of a root organization or when it
     * cannot be resolved.
     */
    public static Organization buildApplicationOrganization(String applicationTenantDomain,
                                                            String eventTenantDomain) {

        if (!isOrganization(eventTenantDomain)) {
            return null;
        }
        return buildOrganizationFromTenantDomain(applicationTenantDomain);
    }

    /**
     * Organization owning the application a login was performed against.
     * <p>
     * Only an event of a sub organization carries this: in a root organization the application and the event
     * belong to the same organization, and naming it adds nothing.
     * <p>
     * The context states the application's organization only for a login performed in a sub organization, which is
     * where the framework needs the distinction. An event of a sub organization published from the organization
     * owning the application does not have it, so the application's own tenant is resolved instead.
     *
     * @param authenticationContext Context of the login.
     * @param eventTenantDomain     Tenant the event belongs to.
     * @return The organization owning the application, or null for an event of a root organization or when it
     * cannot be resolved.
     */
    public static Organization buildApplicationOrganization(AuthenticationContext authenticationContext,
                                                            String eventTenantDomain) {

        if (authenticationContext == null || !isOrganization(eventTenantDomain)) {
            return null;
        }
        String tenantDomain = StringUtils.isNotBlank(authenticationContext.getServiceProviderTenantDomain())
                ? authenticationContext.getServiceProviderTenantDomain() : authenticationContext.getTenantDomain();
        if (StringUtils.isNotBlank(authenticationContext.getServiceProviderOrganizationId())) {
            return buildOrganizationFromOrgId(authenticationContext.getServiceProviderOrganizationId(), tenantDomain);
        }
        return buildOrganizationFromTenantDomain(tenantDomain);
    }

    /**
     * Organization an event belongs to.
     * <p>
     * The tenant of the event is used rather than the organization on the thread: a login to an application shared
     * with a sub organization is published from the organization owning the application, so the thread carries that
     * organization while the event belongs to the one the user logged in to. For every other login, including a
     * login of a root organization, the two are the same.
     *
     * @param tenantDomain Tenant the event belongs to.
     * @return The organization, or the organization on the thread when the tenant cannot be resolved.
     */
    public static Organization resolveEventOrganization(String tenantDomain) {

        Organization organization = buildOrganizationFromTenantDomain(tenantDomain);
        return organization != null ? organization
                : buildOrganizationFromIdentityContext(IdentityContext.getThreadLocalIdentityContext());
    }

    /**
     * Organization a tenant belongs to.
     *
     * @param tenantDomain Tenant to resolve.
     * @return The organization, or null if it could not be resolved.
     */
    public static Organization buildOrganizationFromTenantDomain(String tenantDomain) {

        if (StringUtils.isBlank(tenantDomain)) {
            return null;
        }
        try {
            String organizationId = WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            return buildOrganizationFromOrgId(organizationId, tenantDomain);
        } catch (OrganizationManagementException e) {
            log.debug("Error while resolving the organization of tenant: " + tenantDomain, e);
            return null;
        }
    }

    public static Organization buildOrganizationFromOrgId(String organizationId, String tenantDomain) {

        if (StringUtils.isBlank(organizationId) || StringUtils.isBlank(tenantDomain)) {
            return null;
        }
        try {
            MinimalOrganization minimalOrganization = WSO2EventHookHandlerDataHolder.getInstance().
                    getOrganizationManager().getMinimalOrganization(organizationId, tenantDomain);
            if (minimalOrganization != null) {
                return new Organization(
                        minimalOrganization.getId(),
                        minimalOrganization.getName(),
                        minimalOrganization.getOrganizationHandle(),
                        minimalOrganization.getDepth()
                );
            }
        } catch (OrganizationManagementException e) {
            log.error("Error while getting organization id from orgId " + organizationId, e);
        }
        return null;
    }

    /**
     * Base URL of the resource endpoints referenced from a payload.
     * <p>
     * A resource of a sub organization is addressed through the organization perspective of the root tenant,
     * {@code /t/<root-tenant>/o}, and a resource of a root organization through its own tenant,
     * {@code /t/<tenant>}. The organization is not named in the path: it is carried by the token the reference is
     * resolved with, so its identifier there would produce a path that does not resolve.
     * <p>
     * The tenant of the resource decides this, not the tenant the operation was performed in: an operation
     * performed in an ancestor organization on a resource of a descendant still has to reference the resource
     * where it resides.
     *
     * @param resourceTenantDomain Tenant the resource resides in, or null to fall back to the organization on
     *                             the thread.
     * @return Base URL, or null if it could not be built.
     */
    private static String constructBaseURL(String resourceTenantDomain) {

        try {
            String tenantDomain = StringUtils.isNotBlank(resourceTenantDomain)
                    ? resourceTenantDomain : resolveTenantDomainFromContext();
            if (StringUtils.isBlank(tenantDomain)) {
                return ServiceURLBuilder.create().build().getAbsolutePublicURL();
            }
            if (!isOrganization(tenantDomain)) {
                /* A root organization is qualified by the URL builder rather than by a path built here, so the
                   super tenant rule, the public URL alias of the super tenant and the tenant qualified URL
                   setting all keep applying. Naming the tenant only replaces the one taken from the thread, so a
                   resource of a root organization is referenced exactly as it was before. */
                return ServiceURLBuilder.create().setTenant(tenantDomain).build().getAbsolutePublicURL();
            }
            String rootTenantDomain = resolveRootTenantDomain(tenantDomain);
            if (StringUtils.isBlank(rootTenantDomain)) {
                // Without the root of the hierarchy the organization perspective cannot be addressed, so the
                // URL builder is left to qualify the path as it did before.
                return ServiceURLBuilder.create().build().getAbsolutePublicURL();
            }
            return buildAbsoluteURL("/t/" + rootTenantDomain + "/o");
        } catch (URLBuilderException e) {
            log.debug("Error occurred while building the tenant qualified URL.", e);
        }
        return null;
    }

    /**
     * Build an absolute URL for a path that already carries the tenant or organization perspective. Such a path
     * is used as given: the URL builder qualifies only a path that does not carry one.
     */
    private static String buildAbsoluteURL(String path) throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(path).build().getAbsolutePublicURL();
    }

    /**
     * Tenant of the organization the operation was performed in, used when the resource does not say where it
     * resides.
     */
    private static String resolveTenantDomainFromContext() {

        IdentityContext identityContext = IdentityContext.getThreadLocalIdentityContext();
        if (identityContext.getOrganization() != null &&
                StringUtils.isNotBlank(identityContext.getOrganization().getOrganizationHandle())) {
            return identityContext.getOrganization().getOrganizationHandle();
        }
        if (StringUtils.isNotBlank(identityContext.getTenantDomain())) {
            return identityContext.getTenantDomain();
        }
        RootOrganization rootOrganization = identityContext.getRootOrganization();
        return rootOrganization != null ? rootOrganization.getAssociatedTenantDomain() : null;
    }

    /**
     * Whether the given tenant is a sub organization.
     *
     * @param tenantDomain Tenant to check.
     * @return true if the tenant is a sub organization, false when it is a root tenant or cannot be told.
     */
    public static boolean isOrganization(String tenantDomain) {

        try {
            return OrganizationManagementUtil.isOrganization(tenantDomain);
        } catch (OrganizationManagementException | RuntimeException e) {
            // A reference is descriptive: failing to tell where the resource resides must not fail the payload.
            log.debug("Error while checking whether tenant: " + tenantDomain + " is an organization.", e);
            return false;
        }
    }

    /**
     * Tenant of the root organization of the hierarchy the given tenant belongs to.
     */
    private static String resolveRootTenantDomain(String tenantDomain) {

        String cachedRootTenantDomain = ROOT_TENANT_DOMAINS.get(tenantDomain);
        if (cachedRootTenantDomain != null) {
            return cachedRootTenantDomain;
        }
        String rootTenantDomain = resolveRootTenantDomainFromContext(tenantDomain);
        if (StringUtils.isBlank(rootTenantDomain)) {
            rootTenantDomain = resolveRootTenantDomainFromHierarchy(tenantDomain);
        }
        if (StringUtils.isNotBlank(rootTenantDomain)) {
            ROOT_TENANT_DOMAINS.put(tenantDomain, rootTenantDomain);
        }
        return rootTenantDomain;
    }

    /**
     * The root organization already resolved on this thread, used when the resource belongs to the hierarchy the
     * operation is being performed in. This is the common case, and it avoids a hierarchy walk.
     */
    private static String resolveRootTenantDomainFromContext(String tenantDomain) {

        IdentityContext identityContext = IdentityContext.getThreadLocalIdentityContext();
        RootOrganization rootOrganization = identityContext.getRootOrganization();
        if (rootOrganization == null || StringUtils.isBlank(rootOrganization.getAssociatedTenantDomain())) {
            return null;
        }
        if (identityContext.getOrganization() != null &&
                StringUtils.equals(tenantDomain, identityContext.getOrganization().getOrganizationHandle())) {
            return rootOrganization.getAssociatedTenantDomain();
        }
        return null;
    }

    private static String resolveRootTenantDomainFromHierarchy(String tenantDomain) {

        try {
            OrganizationManager organizationManager =
                    WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager();
            if (organizationManager == null) {
                return null;
            }
            String organizationId = organizationManager.resolveOrganizationId(tenantDomain);
            String rootOrganizationId = organizationManager.getPrimaryOrganizationId(organizationId);
            return organizationManager.resolveTenantDomain(rootOrganizationId);
        } catch (OrganizationManagementException e) {
            log.debug("Error while resolving the root organization of tenant: " + tenantDomain, e);
            return null;
        }
    }

    /**
     * Resolves the user store domain from the event data.
     *
     * @param eventData The event data containing user store information.
     * @return The user store domain name or null if not found.
     */
    public static String resolveUserStoreDomain(EventData eventData) {

        return resolveUserStoreDomain(eventData, eventData != null ? eventData.getTenantDomain() : null);
    }

    /**
     * Resolves the user store domain from the event data, falling back to the primary user store of the given
     * tenant.
     *
     * @param eventData    The event data containing user store information.
     * @param tenantDomain Tenant whose user store to fall back to, which is the tenant the user resides in rather
     *                     than the tenant of the event when the two differ.
     * @return The user store domain name or null if not found.
     */
    public static String resolveUserStoreDomain(EventData eventData, String tenantDomain) {

        if (eventData == null || eventData.getProperties() == null) {
            return null;
        }

        Map<String, Object> properties = eventData.getProperties();
        Object userStoreDomainObj = properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN);
        String userStoreDomainName = (userStoreDomainObj instanceof String) ? (String) userStoreDomainObj : null;

        if (StringUtils.isBlank(userStoreDomainName)) {
            RealmConfiguration realmConfiguration = getRealmConfigurationByTenantDomain(tenantDomain);
            if (realmConfiguration == null) {
                return null;
            }
            userStoreDomainName = realmConfiguration.getUserStoreProperty(
                    UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
        }
        return userStoreDomainName;
    }

    /**
     * Builds a UserStore object based on the event data.
     *
     * @param eventData The event data containing user store information.
     * @return UserStore object or null if the user store domain is not found.
     */
    public static UserStore buildUserStore(EventData eventData) {

        return buildUserStore(eventData, eventData != null ? eventData.getTenantDomain() : null);
    }

    /**
     * Builds a UserStore object, resolving the user store of the given tenant when the event carries none.
     *
     * @param eventData    The event data containing user store information.
     * @param tenantDomain Tenant the user resides in.
     * @return UserStore object or null if the user store domain is not found.
     */
    public static UserStore buildUserStore(EventData eventData, String tenantDomain) {

        String userStoreDomainName = resolveUserStoreDomain(eventData, tenantDomain);
        if (userStoreDomainName == null) {
            return null;
        }

        if (StringUtils.isNotBlank(userStoreDomainName)) {
            return new UserStore(userStoreDomainName);
        }

        return null;
    }

    /**
     * Builds a User object based on the event data.
     *
     * @param eventData The event data containing user information.
     * @return User object or null if user information is not available.
     */
    public static User buildUser(EventData eventData) {

        return buildUser(eventData, eventData != null ? eventData.getTenantDomain() : null);
    }

    /**
     * Builds a User object based on the event data, reading the user from the given tenant.
     *
     * @param eventData    The event data containing user information.
     * @param tenantDomain Tenant the user resides in, which is the tenant its claims are read from and the
     *                     organization its reference is addressed through. It is the tenant of the event only
     *                     when the user resides in the organization the event belongs to.
     * @return User object or null if user information is not available.
     */
    public static User buildUser(EventData eventData, String tenantDomain) {

        if (eventData == null || eventData.getProperties() == null) {
            return null;
        }

        String userName = (String) eventData.getProperties().get(IdentityEventConstants.EventProperty.USER_NAME);

        if (StringUtils.isBlank(userName) && StringUtils.isBlank(eventData.getUserId())) {
            return null;
        }

        User user = new User();
        user.setId(eventData.getUserId());
        user.setRef(constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT, tenantDomain) + "/" + user.getId());

        String userStoreDomain = resolveUserStoreDomain(eventData, tenantDomain);
        UserStoreManager userStoreManager = getUserStoreManagerByTenantDomain(tenantDomain);

        if (userStoreDomain == null || userStoreManager == null) {
            return user;
        }

        try {
            String domainQualifiedUserName = userStoreDomain + "/" + userName;

            if (StringUtils.isBlank(eventData.getUserId())) {
                String userId =
                        userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.USER_ID_CLAIM,
                                UserCoreConstants.DEFAULT_PROFILE);
                user.setId(userId);
            }
            user.setRef(constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT, tenantDomain) + "/" + user.getId());

            String emailAddress =
                    userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                            UserCoreConstants.DEFAULT_PROFILE);

            Optional<UserClaim> emailAddressUserClaimOptional =
                    generateUserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress, tenantDomain);
            emailAddressUserClaimOptional.ifPresent(user::addClaim);
        } catch (UserStoreException e) {
            log.debug("Error while extracting user claims for the user : " + user.getId(), e);
        }

        Optional<UserClaim> userNameOptional = generateUserClaim(USERNAME_CLAIM, userName, tenantDomain);
        userNameOptional.ifPresent(user::addClaim);

        return user;
    }

    /**
     * Builds a Tenant object based on the event data.
     *
     * @return Tenant object with tenant ID and domain.
     */
    public static Tenant buildTenant() {

        RootOrganization rootOrganization = IdentityContext.getThreadLocalIdentityContext()
            .getRootOrganization();
        if (rootOrganization == null) {
            log.debug("Root organization is not available in the identity context.");
            return null;
        }
        String rootTenantId = String.valueOf(rootOrganization.getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(rootOrganization.getAssociatedTenantDomain());

        return new Tenant(rootTenantId, rootTenantDomain);
    }

    /**
     * Checks if the provided grant type is a user-based grant type.
     *
     * @param grantType The grant type to check.
     * @return true if the grant type is user-based, false otherwise.
     */
    public static boolean isUserBasedGrantType(String grantType) {

        return grantType != null && USER_BASED_GRANT_TYPES.contains(grantType);
    }

    /**
     * Retrieves the flow action from the Flow object.
     *
     * @param flow The Flow object.
     * @return The name of the flow action or null if the flow is null.
     */
    public static String getFlowAction(Flow flow) {

        String action = (flow != null) ? flow.getName().name() : null;
        if (action == null) {
            log.debug("Flow action is null.");
        }
        return action;
    }

    /**
     * Retrieves the flow initiator type from the Flow object.
     *
     * @param flow The Flow object.
     * @return The name of the initiating persona or null if the flow or initiating persona is null.
     */
    public static String getFlowInitiatorType(Flow flow) {

        String initiatorType = (flow != null && flow.getInitiatingPersona() != null)
                ? flow.getInitiatingPersona().name() : null;
        if (initiatorType == null) {
            log.debug("Flow initiator type is null.");
        }
        return initiatorType;
    }

    /**
     * Retrieves the flow credential type from the Flow object.
     *
     * @param flow The Flow object.
     * @return The name of the credential type or null if the flow is null, not a credential flow, or credential type is null.
     */
    public static String getFlowCredentialType(Flow flow) {

        String credentialType = (flow != null && Flow.isCredentialFlow(flow.getName())
                && flow.getCredentialType() != null) ? flow.getCredentialType().name() : null;
        if (credentialType == null) {
            log.debug("Flow credential type is null.");
        }
        return credentialType;
    }

    /**
     * Resolves the initiator IP address from the identity context.
     *
     * @return Initiator IP address or null if unavailable.
     */
    public static String resolveInitiatorIpAddress() {

        String initiatorIpAddress = StringUtils.trimToNull(IdentityContextUtil.getClientIpAddress());
        if (initiatorIpAddress == null) {
            log.debug("Initiator IP is not available in the identity context.");
        } else {
            log.debug("Resolved initiator IP from identity context.");
        }
        return initiatorIpAddress;
    }

    public static boolean isFederatedUser(EventData eventData) {

        return Boolean.parseBoolean(String.valueOf(
                eventData.getProperties().get(IdentityEventConstants.EventProperty.IS_FEDERATED_USER)));
    }
}
