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

package org.wso2.identity.webhook.common.event.handler.api.builder;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

/**
 * Interface for User Operation Event Payload Builder.
 */
public interface UserOperationEventPayloadBuilder {

    EventPayload buildUserGroupUpdateEvent(EventData eventData) throws IdentityEventException;

    EventPayload buildUserDeleteEvent(EventData eventData) throws IdentityEventException;

    EventPayload buildUserUnlockAccountEvent(EventData eventData) throws IdentityEventException;

    EventPayload buildUserLockAccountEvent(EventData eventData) throws IdentityEventException;
    EventPayload buildUserProfileUpdateEvent(EventData eventData) throws IdentityEventException;
    EventPayload buildUserAccountEnableEvent(EventData eventData) throws IdentityEventException;
    EventPayload buildUserAccountDisableEvent(EventData eventData) throws IdentityEventException;
    EventPayload buildUserCreatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload of a user shared with an organization.
     *
     * @param eventData Event data.
     * @return Event payload, or null if the schema does not support the event.
     * @throws IdentityEventException If the payload cannot be built.
     */
    default EventPayload buildUserSharedEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    /**
     * Build the payload of a user unshared from an organization.
     *
     * @param eventData Event data.
     * @return Event payload, or null if the schema does not support the event.
     * @throws IdentityEventException If the payload cannot be built.
     */
    default EventPayload buildUserUnsharedEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    /**
     * Get the event schema type.
     *
     * @return Event schema type.
     */
    Constants.EventSchema getEventSchemaType();
}
