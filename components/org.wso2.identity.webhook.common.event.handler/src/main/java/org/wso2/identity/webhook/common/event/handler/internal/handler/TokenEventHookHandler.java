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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.CONSOLE_APP_CONSUMER_KEY;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.IS_FRAGMENT_APP;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.OAUTH2_CLIENT_TYPE;

/**
 * TokenEventHookHandler class.
 * This class is a placeholder for handling token-related events.
 * Currently, it does not contain any methods or properties.
 */
public class TokenEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(TokenEventHookHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. Skipping token event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventForProfile(event, eventData, eventProfile);
            }
        } catch (Exception e) {
            log.warn("Error while retrieving token event publisher configuration for tenant.", e);
        }
    }

    @Override
    public String getName() {

        return Constants.TOKEN_EVENT_HOOK_NAME;
    }

    private void handleEventForProfile(Event event, EventData eventData, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        // Prepare schema, payload builder, and event metadata
        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema schema =
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                        eventProfile.getProfile());
        TokenEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getTokenEventPayloadBuilder(schema);

        if (payloadBuilder == null) {
            log.debug("Skipping token event handling for profile " + eventProfile.getProfile());
            return;
        }

        EventMetadata eventMetadata = EventHookHandlerUtils.getEventProfileManagerByProfile(
                eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            log.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile());
            return;
        }

        // Get channel and event URI
        Channel tokenChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (tokenChannel == null) {
            log.debug("No channel found for token event profile: " + eventProfile.getProfile());
            return;
        }

        String eventUri = tokenChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        if (EventHookHandlerUtils.isSubOrgLevel()) {
            log.debug("Event trigger for sub organization level. Skipping event handling for token event profile: " +
                    eventProfile.getProfile());
            return;
        }

        String applicationKey = resolveApplicationKey(eventData);
        boolean isEventTriggeredForSystemApplication = StringUtils.isNotBlank(applicationKey)
                && CONSOLE_APP_CONSUMER_KEY.equals(applicationKey);
        if (isEventTriggeredForSystemApplication) {
            log.debug("Event trigger for system application: " + applicationKey +
                    ". Skipping event handling for token event profile: " + eventProfile.getProfile());
            return;
        }

        if (isTokenOfSharedApplicationExchange(applicationKey, eventData)) {
            log.debug("Token belongs to the shared application of an organization login exchange. The token of " +
                    "the application the user logged in to is the one published, so this one is skipped for token " +
                    "event profile: " + eventProfile.getProfile());
            return;
        }

        /*
         A token issued through a sub organization is raised in the organization owning the application, so the
         event belongs to the organization being accessed rather than to the tenant it was raised in. The resolved
         tenant replaces the one the event data was built with, so that the payload is built for the same
         organization the event is published to.
         */
        EventData publishingEventData = eventData.toBuilder()
                .tenantDomain(resolvePublishingTenantDomain(eventData))
                .build();
        publishEvent(publishingEventData.getTenantDomain(), tokenChannel, eventUri, eventProfile.getProfile(),
                payloadBuilder, publishingEventData, event.getEventName());
    }

    /**
     * Tenant the token event is published to.
     * <p>
     * For a token issued through a sub organization this is that organization, as it is for the login and session
     * events: the token lets the user act in the organization it is accessing, so that is the organization the
     * event belongs to, whether the user resides there or was shared into it from an ancestor organization. For
     * every other token it is the tenant the token was issued in.
     *
     * @param eventData Data of the token event.
     * @return Tenant domain to publish the event to.
     */
    private String resolvePublishingTenantDomain(EventData eventData) {

        String eventOrganizationId = resolveEventOrganizationId(eventData);
        if (StringUtils.isBlank(eventOrganizationId)) {
            /*
             A token requested through the organization perspective of a tenant keeps that tenant on the thread and
             names the organization separately, so the organization of the context is what the event belongs to.
             */
            return resolveContextOrganizationTenantDomain(eventData);
        }
        try {
            String eventTenantDomain = EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(eventOrganizationId);
            return StringUtils.isNotBlank(eventTenantDomain) ? eventTenantDomain
                    : resolveContextOrganizationTenantDomain(eventData);
        } catch (OrganizationManagementException e) {
            log.warn("Error while resolving the tenant of organization: " + eventOrganizationId, e);
            return resolveContextOrganizationTenantDomain(eventData);
        }
    }

    /**
     * Organization the token was issued through, which is the one the user is accessing with it.
     * <p>
     * The organization the user resides in is taken when the event does not name the one being accessed. They are
     * the same organization for a user residing in the sub organization it logs in to, and differ for a user
     * shared into it, which the event states separately.
     * <p>
     * The event's own statement of whether the user is an organization user is not used: it holds only for a user
     * federated from an organization, as on the legacy organization login flow, while a user authenticating
     * directly against the organization it resides in is not federated and is an organization user all the same.
     *
     * @param eventData Data of the token event.
     * @return Identifier of that organization, or null when the event names none.
     */
    private String resolveEventOrganizationId(EventData eventData) {

        String accessingOrganizationId = getProperty(eventData,
                IdentityEventConstants.EventProperty.ACCESSING_ORGANIZATION_ID);
        return StringUtils.isNotBlank(accessingOrganizationId) ? accessingOrganizationId
                : getProperty(eventData, IdentityEventConstants.EventProperty.USER_RESIDENT_ORGANIZATION_ID);
    }

    private String getProperty(EventData eventData, String propertyName) {

        Object property = eventData.getProperties().get(propertyName);
        return property != null ? StringUtils.trimToNull(String.valueOf(property)) : null;
    }

    /**
     * Tenant of the organization on the thread, which is the organization the event belongs to when the request
     * was made through the organization perspective of a tenant.
     *
     * @param eventData Data of the token event.
     * @return Tenant of that organization, or the tenant of the event when there is none.
     */
    private String resolveContextOrganizationTenantDomain(EventData eventData) {

        Organization organization = IdentityContext.getThreadLocalIdentityContext().getOrganization();
        if (organization == null || StringUtils.isBlank(organization.getOrganizationHandle())
                || organization.getDepth() == 0) {
            return eventData.getTenantDomain();
        }
        return organization.getOrganizationHandle();
    }

    private void publishEvent(String tenantDomain, Channel tokenChannel, String eventUri, String eventProfileName,
                              TokenEventPayloadBuilder payloadBuilder, EventData eventData, String eventName)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(tokenChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(Constants.EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload;
        if ((IdentityEventConstants.Event.TOKEN_REVOKED.equals(eventName))) {
            eventPayload = payloadBuilder.buildAccessTokenRevokeEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2.equals(eventName)) {
            eventPayload = payloadBuilder.buildAccessTokenIssueEvent(eventData);
        } else {
            throw new IdentityRuntimeException("Unsupported event type: " + eventName);
        }

        log.debug("Publishing token event: " + eventName + " for tenant: " + tenantDomain +
                " with event URI: " + eventUri + " and profile: " + eventProfileName);
        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }

    /**
     * Whether the token was issued to the shared application an organization login exchanges through.
     * <p>
     * On the legacy organization login flow the authenticator authenticates the user against the application
     * shared with the sub organization, and that exchange issues a token of its own. The token of the application
     * the user actually logged in to is issued separately and is the one worth publishing, so the exchange's token
     * is skipped. The enhanced flow issues no such token, and its applications are left alone.
     *
     * @param applicationKey Consumer key the token was issued to.
     * @param eventData      Data of the token event.
     * @return true if the token belongs to such an exchange.
     */
    private boolean isTokenOfSharedApplicationExchange(String applicationKey, EventData eventData) {

        if (StringUtils.isBlank(applicationKey)) {
            return false;
        }
        try {
            ApplicationManagementService applicationManagementService =
                    EventHookHandlerDataHolder.getInstance().getApplicationManagementService();
            ServiceProvider serviceProvider = applicationManagementService.getServiceProviderByClientId(
                    applicationKey, OAUTH2_CLIENT_TYPE, eventData.getTenantDomain());
            if (serviceProvider == null || serviceProvider.getSpProperties() == null || !Arrays.stream(
                    serviceProvider.getSpProperties()).anyMatch(property -> IS_FRAGMENT_APP.equals(property.getName())
                    && Boolean.parseBoolean(property.getValue()))) {
                return false;
            }
            String mainApplicationId =
                    applicationManagementService.getMainAppId(serviceProvider.getApplicationResourceId());
            if (StringUtils.isBlank(mainApplicationId)) {
                return false;
            }
            String mainApplicationTenantDomain = IdentityTenantUtil.getTenantDomain(
                    applicationManagementService.getTenantIdByApp(mainApplicationId));
            ServiceProvider mainApplication = applicationManagementService.getApplicationByResourceId(
                    mainApplicationId, mainApplicationTenantDomain);
            // The enhanced flow works against one application only, so its events are the only ones there are.
            return mainApplication != null && !mainApplication.isEnhancedOrganizationAuthenticationEnabled();
        } catch (IdentityApplicationManagementException e) {
            log.warn("Error while checking whether the token was issued to a shared application: " + applicationKey,
                    e);
            return false;
        }
    }

    private String resolveApplicationKey(EventData eventData) {

        if (eventData == null) {
            return null;
        }

        if (eventData.getProperties().get(IdentityEventConstants.EventProperty.CONSUMER_KEY) != null) {
            String consumerKey = String.valueOf(eventData.getProperties()
                    .get(IdentityEventConstants.EventProperty.CONSUMER_KEY));
            if (StringUtils.isNotBlank(consumerKey)) {
                return consumerKey;
            }
        } else {
            Object consumerKeysObj = eventData.getProperties().get(IdentityEventConstants.EventProperty.CONSUMER_KEYS);
            if (consumerKeysObj instanceof Collection) {
                Collection<?> consumerKeys = (Collection<?>) consumerKeysObj;
                if (consumerKeys.size() == 1) {
                    Object key = consumerKeys.iterator().next();
                    if (key instanceof String) {
                        return (String) key;
                    }
                }
            }
        }
        return null;
    }
}
