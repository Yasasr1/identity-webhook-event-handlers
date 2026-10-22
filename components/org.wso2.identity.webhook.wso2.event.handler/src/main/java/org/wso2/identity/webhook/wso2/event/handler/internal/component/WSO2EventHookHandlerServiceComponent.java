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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.consent.mgt.core.ConsentManager;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.builder.OrganizationManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.RoleManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.service.EventProfileManager;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2ConsentEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2OrganizationManagementEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2ConsentPurposeEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2RoleManagementEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2TokenEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.internal.service.impl.WSO2EventProfileManager;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2LoginEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2SessionEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2UserOperationEventPayloadBuilder;

/**
 * WSO2 Event Handler service component class.
 */
@Component(
        name = "org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerServiceComponent",
        immediate = true)
public class WSO2EventHookHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(WSO2EventHookHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            log.debug("WSO2 Event Handler is activated.");

            context.getBundleContext().registerService(EventProfileManager.class.getName(),
                    new WSO2EventProfileManager(), null);

            context.getBundleContext().registerService(LoginEventPayloadBuilder.class.getName(),
                    new WSO2LoginEventPayloadBuilder(), null);
            context.getBundleContext().registerService(UserOperationEventPayloadBuilder.class.getName(),
                    new WSO2UserOperationEventPayloadBuilder(), null);
            context.getBundleContext().registerService(SessionEventPayloadBuilder.class.getName(),
                    new WSO2SessionEventPayloadBuilder(), null);
            context.getBundleContext().registerService(CredentialEventPayloadBuilder.class.getName(),
                    new WSO2CredentialEventPayloadBuilder(), null);
            context.getBundleContext().registerService(RegistrationEventPayloadBuilder.class.getName(),
                    new WSO2RegistrationEventPayloadBuilder(), null);
            context.getBundleContext().registerService(TokenEventPayloadBuilder.class.getName(),
                    new WSO2TokenEventPayloadBuilder(), null);

            context.getBundleContext().registerService(
                    org.wso2.identity.webhook.common.event.handler.api.builder.ConsentPurposeEventPayloadBuilder.class
                            .getName(),
                    new WSO2ConsentPurposeEventPayloadBuilder(), null);
            context.getBundleContext().registerService(
                    org.wso2.identity.webhook.common.event.handler.api.builder.ConsentEventPayloadBuilder.class
                            .getName(),
                    new WSO2ConsentEventPayloadBuilder(), null);
            context.getBundleContext().registerService(RoleManagementEventPayloadBuilder.class.getName(),
                    new WSO2RoleManagementEventPayloadBuilder(), null);
            context.getBundleContext().registerService(OrganizationManagementEventPayloadBuilder.class.getName(),
                    new WSO2OrganizationManagementEventPayloadBuilder(), null);
        } catch (Exception e) {
            log.error("Error while activating event handler.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        log.debug("WSO2 Event Handler is deactivated.");
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("UnSetting the Realm Service");
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(null);
    }

    /**
     * Set claim metadata management service implementation.
     *
     * @param claimMetadataManagementService ClaimMetadataManagementService
     */
    @Reference(
            name = "claimMetadataManagementService",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimMetadataManagementService")
    protected void setClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Claim Metadata Service");
        }
        WSO2EventHookHandlerDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataManagementService);
    }

    /**
     * Unset claim metadata management service implementation.
     */
    protected void unsetClaimMetadataManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        log.debug("UnSetting the Claim Metadata Service");
        WSO2EventHookHandlerDataHolder.getInstance().setClaimMetadataManagementService(null);
    }

    /**
     * Set user session management service implementation.
     *
     * @param userSessionManagementService UserSessionManagementService instance
     */
    @Reference(
            name = "userSessionManagementService",
            service = UserSessionManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetUserSessionManagementService")
    protected void setUserSessionManagementService(UserSessionManagementService userSessionManagementService) {

        log.debug("Setting the User Session Management Service");
        WSO2EventHookHandlerDataHolder.getInstance().setUserSessionManagementService(userSessionManagementService);
    }

    /**
     * Unset user session management service implementation.
     *
     * @param userSessionManagementService UserSessionManagementService instance
     */
    protected void unsetUserSessionManagementService(UserSessionManagementService userSessionManagementService) {

        log.debug("Unsetting the User Session Management Service");
        WSO2EventHookHandlerDataHolder.getInstance().setUserSessionManagementService(null);
    }

    /**
     * Set application management service implementation.
     *
     * @param applicationManagementService ApplicationManagementService instance
     */
    @Reference(
            name = "application.management.service.component",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService")
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        log.debug("Setting the Application Management Service");
        WSO2EventHookHandlerDataHolder.getInstance().setApplicationManagementService(applicationManagementService);
    }

    /**
     * Unset application management service implementation.
     *
     * @param applicationManagementService ApplicationManagementService instance
     */
    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        log.debug("Unsetting the Application Management Service");
        WSO2EventHookHandlerDataHolder.getInstance().setApplicationManagementService(null);
    }

    @Reference(
            name = "consent.manager",
            service = ConsentManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConsentManager")
    protected void setConsentManager(ConsentManager consentManager) {

        log.debug("Setting the Consent Manager");
        WSO2EventHookHandlerDataHolder.getInstance().setConsentManager(consentManager);
    }

    protected void unsetConsentManager(ConsentManager consentManager) {

        log.debug("Unsetting the Consent Manager");
        WSO2EventHookHandlerDataHolder.getInstance().setConsentManager(null);
    }

    /**
     * Set role management service implementation.
     *
     * @param roleManagementService RoleManagementService instance
     */
    @Reference(
            name = "role.management.service.component",
            service = RoleManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRoleManagementService")
    protected void setRoleManagementService(RoleManagementService roleManagementService) {

        log.debug("Setting the Role Management Service");
        WSO2EventHookHandlerDataHolder.getInstance().setRoleManagementService(roleManagementService);
    }

    /**
     * Unset role management service implementation.
     *
     * @param roleManagementService RoleManagementService instance
     */
    protected void unsetRoleManagementService(RoleManagementService roleManagementService) {

        log.debug("Unsetting the Role Management Service");
        WSO2EventHookHandlerDataHolder.getInstance().setRoleManagementService(null);
    }

    /**
     * Set IdP manager implementation.
     *
     * @param idpManager IdpManager instance
     */
    @Reference(
            name = "idp.manager.component",
            service = IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdpManager")
    protected void setIdpManager(IdpManager idpManager) {

        log.debug("Setting the IdP Manager");
        WSO2EventHookHandlerDataHolder.getInstance().setIdpManager(idpManager);
    }

    /**
     * Unset IdP manager implementation.
     *
     * @param idpManager IdpManager instance
     */
    protected void unsetIdpManager(IdpManager idpManager) {

        log.debug("Unsetting the IdP Manager");
        WSO2EventHookHandlerDataHolder.getInstance().setIdpManager(null);
    }

    /**
     * Set organization user sharing service implementation. Used to tell the payloads of a shared user's profile
     * which user it belongs to.
     *
     * @param organizationUserSharingService OrganizationUserSharingService instance
     */
    @Reference(
            name = "organization.user.sharing.service.component",
            service = OrganizationUserSharingService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserSharingService")
    protected void setOrganizationUserSharingService(OrganizationUserSharingService organizationUserSharingService) {

        log.debug("Setting the Organization User Sharing Service");
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationUserSharingService(organizationUserSharingService);
    }

    /**
     * Unset organization user sharing service implementation.
     *
     * @param organizationUserSharingService OrganizationUserSharingService instance
     */
    protected void unsetOrganizationUserSharingService(
            OrganizationUserSharingService organizationUserSharingService) {

        log.debug("Unsetting the Organization User Sharing Service");
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationUserSharingService(null);
    }
}
