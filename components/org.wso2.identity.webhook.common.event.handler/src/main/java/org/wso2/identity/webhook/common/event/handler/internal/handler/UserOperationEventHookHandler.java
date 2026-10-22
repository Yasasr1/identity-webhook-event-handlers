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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.UserSharingEvent;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.PRE_DELETE_USER_ID;

/**
 * User Operation Event Hook Handler.
 */
public class UserOperationEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(UserOperationEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.USER_OPERATION_EVENT_HOOK_NAME;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        boolean canHandle = false;
        try {
            if (!(messageContext instanceof IdentityEventMessageContext)) {
                log.debug("MessageContext is not of type IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            IdentityEventMessageContext identityContext = (IdentityEventMessageContext) messageContext;
            String eventName = identityContext.getEvent() != null ? identityContext.getEvent().getEventName() : null;
            if (eventName == null) {
                log.debug("Event name is null in IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            canHandle = isSupportedEvent(eventName);
            if (canHandle) {
                log.debug(eventName + " event can be handled.");
            } else {
                log.debug(eventName + " event cannot be handled.");
            }
        } catch (Exception e) {
            log.warn("Unexpected error occurred while evaluating event in UserOperationEventHookHandler.", e);
        }
        return canHandle;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            if (IdentityEventConstants.Event.PRE_DELETE_USER_WITH_ID.equals(event.getEventName())) {
                String userId = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_ID);
                IdentityUtil.threadLocalProperties.get().put(PRE_DELETE_USER_ID, userId);
                return;
            }
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                log.warn(
                        "No event profiles found in the webhook metadata service. Skipping user operation event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventPerProfile(event, eventProfile);
            }
        } catch (Exception e) {
            log.warn("Error while retrieving event publisher configuration for tenant.", e);
        }
    }

    private void handleEventPerProfile(Event event, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        // Prepare schema, payload builder, and event metadata
        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema schema =
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                        eventProfile.getProfile());
        UserOperationEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getUserOperationEventPayloadBuilder(schema);
        if (payloadBuilder == null) {
            log.debug("Skipping user operation event handling for profile " + eventProfile.getProfile());
            return;
        }
        EventMetadata eventMetadata =
                EventHookHandlerUtils.getEventProfileManagerByProfile(eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            log.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile());
            return;
        }
        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
        String tenantDomain = eventData.getTenantDomain();

        // Get channel and event URI
        Channel userOperationChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (userOperationChannel == null) {
            log.debug("No channel found for user operation event profile: " + eventProfile.getProfile());
            return;
        }
        String eventUri = userOperationChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        // Publish for current accessing org
        publishUserOperationEvent(tenantDomain, userOperationChannel, eventUri, eventProfile.getProfile(),
                payloadBuilder, eventData, event.getEventName());
    }

    private boolean isSupportedEvent(String eventName) {

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        Flow.Name flowName = (flow != null) ? flow.getName() : null;
        return !Flow.Name.BULK_RESOURCE_UPDATE.equals(flowName) &&
                (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(eventName) ||
                        IdentityEventConstants.Event.PRE_DELETE_USER_WITH_ID.equals(eventName) ||
                        IdentityEventConstants.Event.POST_DELETE_USER.equals(eventName) ||
                        IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT.equals(eventName) ||
                        IdentityEventConstants.Event.POST_LOCK_ACCOUNT.equals(eventName) ||
                        IdentityEventConstants.Event.POST_USER_PROFILE_UPDATE.equals(eventName) ||
                        IdentityEventConstants.Event.POST_DISABLE_ACCOUNT.equals(eventName) ||
                        IdentityEventConstants.Event.POST_ENABLE_ACCOUNT.equals(eventName) ||
                        IdentityEventConstants.Event.POST_ADD_USER.equals(eventName) ||
                        UserSharingEvent.POST_SHARE_USER.equals(eventName) ||
                        UserSharingEvent.POST_UNSHARE_USER.equals(eventName));
    }

    private boolean isUserCreatedFlow(String eventName) {

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        Flow.Name flowName = (flow != null) ? flow.getName() : null;
        /*
        All POST_ADD_USER events will result in a userCreated event payload.
        Since user creation does not imply successful registration,
        this check is valid and does not cause any issues.
         */
        return IdentityEventConstants.Event.POST_ADD_USER.equals(eventName) &&
                !Flow.Name.BULK_RESOURCE_UPDATE.equals(flowName);
    }

    private void publishUserOperationEvent(String tenantDomain, Channel userOperationChannel, String eventUri,
                                           String eventProfileName, UserOperationEventPayloadBuilder payloadBuilder,
                                           EventData eventData, String eventName)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(userOperationChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload = null;
        if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserGroupUpdateEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_DELETE_USER.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserDeleteEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserUnlockAccountEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_LOCK_ACCOUNT.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserLockAccountEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_USER_PROFILE_UPDATE.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserProfileUpdateEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_ENABLE_ACCOUNT.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserAccountEnableEvent(eventData);
        } else if (IdentityEventConstants.Event.POST_DISABLE_ACCOUNT.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserAccountDisableEvent(eventData);
        } else if (isUserCreatedFlow(eventName)) {
            eventPayload = payloadBuilder.buildUserCreatedEvent(eventData);
        } else if (UserSharingEvent.POST_SHARE_USER.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserSharedEvent(eventData);
        } else if (UserSharingEvent.POST_UNSHARE_USER.equals(eventName)) {
            eventPayload = payloadBuilder.buildUserUnsharedEvent(eventData);
        } else {
            log.debug("Unsupported user operation event: " + eventName);
            return;
        }

        if (eventPayload == null) {
            log.debug("No payload built for user operation event: " + eventName);
            return;
        }
        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }
}
