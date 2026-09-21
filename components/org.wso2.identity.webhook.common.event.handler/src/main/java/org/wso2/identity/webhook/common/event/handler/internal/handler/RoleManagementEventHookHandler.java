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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.RoleManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.ROLE_MANAGEMENT_EVENT_HOOK_NAME;

/**
 * Role Management Event Hook Handler.
 * Subscribes to V2 role lifecycle Carbon events and publishes them as webhook events.
 */
public class RoleManagementEventHookHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(RoleManagementEventHookHandler.class);

    @Override
    public String getName() {

        return ROLE_MANAGEMENT_EVENT_HOOK_NAME;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        try {
            if (!(messageContext instanceof IdentityEventMessageContext identityContext)) {
                LOG.debug("MessageContext is not of type IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            String eventName = identityContext.getEvent() != null ? identityContext.getEvent().getEventName() : null;
            if (eventName == null) {
                LOG.debug("Event name is null in IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            boolean canHandle = isSupportedEvent(eventName);
            if (LOG.isDebugEnabled()) {
                LOG.debug(eventName + (canHandle ? " event can be handled." : " event cannot be handled."));
            }
            return canHandle;
        } catch (Exception e) {
            LOG.warn("Unexpected error occurred while evaluating event in RoleManagementEventHookHandler.", e);
            return false;
        }
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                LOG.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping role management event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventPerProfile(event, eventProfile);
            }
        } catch (Exception e) {
            LOG.warn("Error while handling role management event: " + event.getEventName(), e);
        }
    }

    private void handleEventPerProfile(Event event, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        Constants.EventSchema schema =
                Constants.EventSchema.valueOf(eventProfile.getProfile());
        RoleManagementEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getRoleManagementEventPayloadBuilder(schema);
        if (payloadBuilder == null) {
            LOG.debug("Skipping role management event handling for profile " + eventProfile.getProfile());
            return;
        }
        EventMetadata eventMetadata =
                EventHookHandlerUtils.getEventProfileManagerByProfile(eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            LOG.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile());
            return;
        }
        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
        String tenantDomain = eventData.getTenantDomain();

        Channel roleChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (roleChannel == null) {
            LOG.debug("No channel found for role management event profile: " + eventProfile.getProfile());
            return;
        }
        String eventUri = roleChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        publishRoleManagementEvent(tenantDomain, roleChannel, eventUri, eventProfile.getProfile(),
                payloadBuilder, eventData, event.getEventName());
    }

    private boolean isSupportedEvent(String eventName) {

        return IdentityEventConstants.Event.POST_ADD_ROLE_V2_EVENT.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_ROLE_V2_NAME_EVENT.equals(eventName) ||
                IdentityEventConstants.Event.POST_DELETE_ROLE_V2_EVENT.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE_V2_EVENT.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_GROUP_LIST_OF_ROLE_V2_EVENT.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_IDP_GROUP_LIST_OF_ROLE_V2_EVENT.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_PERMISSIONS_FOR_ROLE_V2_EVENT.equals(eventName);
    }

    private void publishRoleManagementEvent(String tenantDomain, Channel roleChannel, String eventUri,
                                            String eventProfileName, RoleManagementEventPayloadBuilder payloadBuilder,
                                            EventData eventData, String eventName)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(roleChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(EVENT_PROFILE_VERSION)
                .build();

        EventPayload eventPayload;
        if (IdentityEventConstants.Event.POST_ADD_ROLE_V2_EVENT.equals(eventName)) {
            eventPayload = payloadBuilder.buildRoleCreatedEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_UPDATE_ROLE_V2_NAME_EVENT.equals(eventName)) {
            eventPayload = payloadBuilder.buildRoleMetaUpdatedEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_DELETE_ROLE_V2_EVENT.equals(eventName)) {
            eventPayload = payloadBuilder.buildRoleDeletedEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE_V2_EVENT.equals(eventName)) {
            eventPayload = payloadBuilder.buildRoleUsersUpdatedEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_UPDATE_GROUP_LIST_OF_ROLE_V2_EVENT.equals(eventName)) {
            eventPayload = payloadBuilder.buildRoleGroupsUpdatedEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_UPDATE_IDP_GROUP_LIST_OF_ROLE_V2_EVENT.equals(eventName)) {
            eventPayload = payloadBuilder.buildRoleIdpGroupsUpdatedEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_UPDATE_PERMISSIONS_FOR_ROLE_V2_EVENT.equals(eventName)) {
            eventPayload = payloadBuilder.buildRolePermissionsUpdatedEvent(eventData);
        } else {
            LOG.debug("Unsupported role management event: " + eventName);
            return;
        }

        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }
}
