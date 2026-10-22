/*
 * Copyright (c) 2025-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.wso2.event.handler.internal.service.impl;

import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.identity.webhook.common.event.handler.api.service.EventProfileManager;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.UserSharingEvent;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;

import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.CONSENT_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.CONSENT_PURPOSE_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.CREDENTIAL_CHANGE_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.LOGIN_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.ORGANIZATION_MGT_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.ROLE_MANAGEMENT_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.SESSION_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.TOKEN_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.LOGIN_FAILURE_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.LOGIN_SUCCESS_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ACCOUNT_DISABLE_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ACCOUNT_ENABLE_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_DELETE_USER_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_LOCK_ACCOUNT_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UNLOCK_ACCOUNT_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UPDATE_USER_CREDENTIAL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UPDATE_USER_LIST_OF_ROLE_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_USER_CREATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_USER_SHARED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_USER_UNSHARED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_USER_PROFILE_UPDATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.CONSENT_ADDED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.CONSENT_REVOKED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.CONSENT_PURPOSE_VERSION_ADDED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.ROLE_CREATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.ROLE_DELETED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.ROLE_GROUPS_UPDATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.ROLE_IDP_GROUPS_UPDATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.ROLE_PERMISSIONS_UPDATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.ROLE_META_UPDATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.ROLE_USERS_UPDATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ORGANIZATION_CREATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ORGANIZATION_DELETED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ORGANIZATION_UPDATED_EVENT;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_ADD_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_DELETE_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_PATCH_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_POST_UPDATE_ORGANIZATION;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_CREATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_PRESENTED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_REVOKED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.TOKEN_ISSUED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.TOKEN_REVOKED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_ADD_PURPOSE_VERSION;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_ADD_RECEIPT;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_AUTHORIZE_CONSENT;

/**
 * This class is responsible for resolving the event metadata for WSO2 events.
 */
public class WSO2EventProfileManager implements EventProfileManager {

    @Override
    public EventMetadata resolveEventMetadata(String event) {

        return resolveEventHandlerKey(event);
    }

    private EventMetadata resolveEventHandlerKey(String eventName) {

        String event = null;
        String channel = null;

        if (!isBulkOperation()) {
            if (Objects.requireNonNull(eventName).equals(
                    IdentityEventConstants.Event.AUTHENTICATION_SUCCESS)) {
                channel = LOGIN_CHANNEL;
                event = LOGIN_SUCCESS_EVENT;
            } else if (IdentityEventConstants.Event.AUTHENTICATION_STEP_FAILURE.equals(eventName)) {
                channel = LOGIN_CHANNEL;
                event = LOGIN_FAILURE_EVENT;
            } else if (IdentityEventConstants.Event.SESSION_TERMINATE_V2.equals(eventName)) {
                channel = SESSION_CHANNEL;
                event = SESSION_REVOKED_EVENT;
            } else if (IdentityEventConstants.Event.SESSION_UPDATE.equals(eventName) ||
                    IdentityEventConstants.Event.SESSION_EXTENSION.equals(eventName)) {
                channel = SESSION_CHANNEL;
                event = SESSION_PRESENTED_EVENT;
            } else if (IdentityEventConstants.Event.SESSION_CREATE.equals(eventName)) {
                channel = SESSION_CHANNEL;
                event = SESSION_CREATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_UPDATE_USER_LIST_OF_ROLE_EVENT;
            } else if (IdentityEventConstants.Event.POST_DELETE_USER.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_DELETE_USER_EVENT;
            } else if (IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_UNLOCK_ACCOUNT_EVENT;
            } else if (IdentityEventConstants.Event.POST_LOCK_ACCOUNT.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_LOCK_ACCOUNT_EVENT;
            } else if (IdentityEventConstants.Event.POST_USER_PROFILE_UPDATE.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_USER_PROFILE_UPDATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_ENABLE_ACCOUNT.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_ACCOUNT_ENABLE_EVENT;
            } else if (IdentityEventConstants.Event.POST_DISABLE_ACCOUNT.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_ACCOUNT_DISABLE_EVENT;
            } else if (isCredentialUpdateFlow(eventName)) {
                channel = CREDENTIAL_CHANGE_CHANNEL;
                event = POST_UPDATE_USER_CREDENTIAL;
            } else if (IdentityEventConstants.Event.POST_ADD_USER.equals(eventName)) {
                /*
                The user operation check must always precede the registration check, since user creation occurs before
                registration, and both events are triggered by the same event: POST_ADD_USER.
                // TODO this issue is due to sequence utility access of metadata.
                 */
                channel = USER_OPERATION_CHANNEL;
                event = POST_USER_CREATED_EVENT;
            } else if (UserSharingEvent.POST_SHARE_USER.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_USER_SHARED_EVENT;
            } else if (UserSharingEvent.POST_UNSHARE_USER.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_USER_UNSHARED_EVENT;
            } else if (IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2.equals(eventName)) {
                channel = TOKEN_CHANNEL;
                event = TOKEN_ISSUED_EVENT;
            } else if (IdentityEventConstants.Event.TOKEN_REVOKED.equals(eventName)) {
                channel = TOKEN_CHANNEL;
                event = TOKEN_REVOKED_EVENT;
            } else if (POST_ADD_PURPOSE_VERSION.equals(eventName)) {
                channel = CONSENT_PURPOSE_CHANNEL;
                event = CONSENT_PURPOSE_VERSION_ADDED_EVENT;
            } else if (POST_ADD_RECEIPT.equals(eventName)) {
                channel = CONSENT_CHANNEL;
                event = CONSENT_ADDED_EVENT;
            } else if (POST_AUTHORIZE_CONSENT.equals(eventName)) {
                channel = CONSENT_CHANNEL;
                Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
                event = (flow != null && Flow.Name.CONSENT_REVOKE.equals(flow.getName()))
                        ? CONSENT_REVOKED_EVENT : CONSENT_ADDED_EVENT;
            } else if (IdentityEventConstants.Event.POST_ADD_ROLE_V2_EVENT.equals(eventName)) {
                channel = ROLE_MANAGEMENT_CHANNEL;
                event = ROLE_CREATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_UPDATE_ROLE_V2_NAME_EVENT.equals(eventName)) {
                channel = ROLE_MANAGEMENT_CHANNEL;
                event = ROLE_META_UPDATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_DELETE_ROLE_V2_EVENT.equals(eventName)) {
                channel = ROLE_MANAGEMENT_CHANNEL;
                event = ROLE_DELETED_EVENT;
            } else if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE_V2_EVENT.equals(eventName)) {
                channel = ROLE_MANAGEMENT_CHANNEL;
                event = ROLE_USERS_UPDATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_UPDATE_GROUP_LIST_OF_ROLE_V2_EVENT.equals(eventName)) {
                channel = ROLE_MANAGEMENT_CHANNEL;
                event = ROLE_GROUPS_UPDATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_UPDATE_IDP_GROUP_LIST_OF_ROLE_V2_EVENT.equals(eventName)) {
                channel = ROLE_MANAGEMENT_CHANNEL;
                event = ROLE_IDP_GROUPS_UPDATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_UPDATE_PERMISSIONS_FOR_ROLE_V2_EVENT.equals(eventName)) {
                channel = ROLE_MANAGEMENT_CHANNEL;
                event = ROLE_PERMISSIONS_UPDATED_EVENT;
            } else if (EVENT_POST_ADD_ORGANIZATION.equals(eventName)) {
                channel = ORGANIZATION_MGT_CHANNEL;
                event = POST_ORGANIZATION_CREATED_EVENT;
            } else if (EVENT_POST_PATCH_ORGANIZATION.equals(eventName) ||
                    EVENT_POST_UPDATE_ORGANIZATION.equals(eventName)) {
                channel = ORGANIZATION_MGT_CHANNEL;
                event = POST_ORGANIZATION_UPDATED_EVENT;
            } else if (EVENT_POST_DELETE_ORGANIZATION.equals(eventName)) {
                channel = ORGANIZATION_MGT_CHANNEL;
                event = POST_ORGANIZATION_DELETED_EVENT;
            }
        }
        return EventMetadata.builder()
                .event(String.valueOf(event))
                .channel(String.valueOf(channel))
                .eventProfile(WSO2.name())
                .build();
    }

    private boolean isBulkOperation() {

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        Flow.Name flowName = (flow != null) ? flow.getName() : null;

        return Flow.Name.BULK_RESOURCE_UPDATE.equals(flowName);
    }

    private boolean isCredentialUpdateFlow(String eventName) {

        /*
        Event.POST_ADD_NEW_PASSWORD + Flow.Name.CREDENTIAL_RESET:
            Triggered when a user resets their password, either:
                After an admin-enforced password reset, or
                Through the "Forgot Password" flow.

        Event.POST_UPDATE_CREDENTIAL_BY_SCIM:
            Triggered when:
                A user resets their password via the My Account portal, or
                An admin resets the user's password via the Console.

        Event.POST_UPDATE_CREDENTIAL_BY_ME_API:
            Triggered when:
                A user updates their password via the user password update API.
         */
        if (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName)) {
            Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
            Flow.Name flowName = (flow != null) ? flow.getName() : null;

            return Flow.Name.CREDENTIAL_RESET.equals(flowName);
        }

        return IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_ME_API.equals(eventName);
    }
}
