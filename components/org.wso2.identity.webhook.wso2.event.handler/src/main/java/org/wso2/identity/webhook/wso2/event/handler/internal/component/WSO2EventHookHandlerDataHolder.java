/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.wso2.event.handler.internal.component;

import org.wso2.carbon.consent.mgt.core.ConsentManager;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * A data holder class to keep the data of the event handler component.
 */
public class WSO2EventHookHandlerDataHolder {

    private static final WSO2EventHookHandlerDataHolder instance = new WSO2EventHookHandlerDataHolder();
    private OrganizationManager organizationManager;
    private RealmService realmService;
    private ClaimMetadataManagementService claimMetadataManagementService;
    private ApplicationManagementService applicationManagementService;
    private RoleManagementService roleManagementService;
    private OrganizationUserSharingService organizationUserSharingService;
    private IdpManager idpManager;

    private UserSessionManagementService userSessionManagementService;
    private ConsentManager consentManager;

    private WSO2EventHookHandlerDataHolder() {

    }

    public static WSO2EventHookHandlerDataHolder getInstance() {

        return instance;
    }

    /**
     * Get {@link OrganizationManager}.
     *
     * @return organization manager instance {@link OrganizationManager}.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set {@link OrganizationManager}.
     *
     * @param organizationManager Instance of {@link OrganizationManager}.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    /**
     * Get {@link RealmService}.
     *
     * @return realm service instance {@link RealmService}.
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set {@link RealmService}.
     *
     * @param realmService Instance of {@link RealmService}.
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    /**
     * Get the claim metadata management service.
     *
     * @return Claim metadata management service.
     */
    public ClaimMetadataManagementService getClaimMetadataManagementService() {

        return claimMetadataManagementService;
    }

    /*
     * Set the claim metadata management service.
     *
     * @param claimMetadataManagementService Claim metadata management service.
     */
    public void setClaimMetadataManagementService(
            ClaimMetadataManagementService claimMetadataManagementService) {

        this.claimMetadataManagementService = claimMetadataManagementService;
    }

    /**
     * Get the user session management service.
     *
     * @return UserSessionManagementService instance.
     */
    public UserSessionManagementService getUserSessionManagementService() {

        return userSessionManagementService;
    }

    /**
     * Set the user session management service.
     *
     * @param userSessionManagementService UserSessionManagementService instance.
     */
    public void setUserSessionManagementService(
            UserSessionManagementService userSessionManagementService) {

        this.userSessionManagementService = userSessionManagementService;
    }

    /**
     * Get the application management service.
     *
     * @return ApplicationManagementService instance.
     */
    public ApplicationManagementService getApplicationManagementService() {

        return applicationManagementService;
    }

    /**
     * Set the application management service.
     *
     * @param applicationManagementService ApplicationManagementService instance.
     */
    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        this.applicationManagementService = applicationManagementService;
    }

    /**
     * Get the consent manager.
     *
     * @return ConsentManager instance.
     */
    public ConsentManager getConsentManager() {

        return consentManager;
    }

    /**
     * Set the consent manager.
     *
     * @param consentManager ConsentManager instance.
     */
    public void setConsentManager(ConsentManager consentManager) {

        this.consentManager = consentManager;
    }

    /**
     * Get the role management service.
     *
     * @return RoleManagementService instance.
     */
    public RoleManagementService getRoleManagementService() {

        return roleManagementService;
    }

    /**
     * Set the role management service.
     *
     * @param roleManagementService RoleManagementService instance.
     */
    public void setRoleManagementService(RoleManagementService roleManagementService) {

        this.roleManagementService = roleManagementService;
    }

    /**
     * Get the IdP manager.
     *
     * @return IdpManager instance.
     */
    public IdpManager getIdpManager() {

        return idpManager;
    }

    /**
     * Set the IdP manager.
     *
     * @param idpManager IdpManager instance.
     */
    public void setIdpManager(IdpManager idpManager) {

        this.idpManager = idpManager;
    }

    /**
     * Get the organization user sharing service.
     *
     * @return OrganizationUserSharingService instance, or null when it is not available.
     */
    public OrganizationUserSharingService getOrganizationUserSharingService() {

        return organizationUserSharingService;
    }

    /**
     * Set the organization user sharing service.
     *
     * @param organizationUserSharingService OrganizationUserSharingService instance.
     */
    public void setOrganizationUserSharingService(OrganizationUserSharingService organizationUserSharingService) {

        this.organizationUserSharingService = organizationUserSharingService;
    }
}
