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

package org.wso2.identity.webhook.common.event.handler.api.constants;

/**
 * Constants class.
 */
public class Constants {

    /**
     * This enum represents the event schema types.
     */
    public enum EventSchema {
        WSO2,
        CAEP,
        RISC;

        EventSchema() {

        }
    }

    /**
     * This class represents the event channels.
     */
    public static class Channel {

        public static final String LOGIN_CHANNEL = "https://schemas.identity.wso2.org/events/login";
        public static final String CREDENTIAL_CHANGE_CHANNEL = "https://schemas.identity.wso2.org/events/credential";
        public static final String REGISTRATION_CHANNEL = "https://schemas.identity.wso2.org/events/registration";
        public static final String USER_OPERATION_CHANNEL = "https://schemas.identity.wso2.org/events/user";
        public static final String VERIFICATION_CHANNEL = "https://schemas.identity.wso2.org/events/verification";
        public static final String SESSION_CHANNEL = "https://schemas.identity.wso2.org/events/session";
        public static final String TOKEN_CHANNEL = "https://schemas.identity.wso2.org/events/token";
        public static final String CONSENT_CHANNEL = "https://schemas.identity.wso2.org/events/consent";
        public static final String CONSENT_PURPOSE_CHANNEL = "https://schemas.identity.wso2.org/events/consent-purpose";
        public static final String ROLE_MANAGEMENT_CHANNEL = "https://schemas.identity.wso2.org/events/role";
        public static final String ORGANIZATION_MGT_CHANNEL = "https://schemas.identity.wso2.org/events/organization";
    }

    /**
     * This class represents the identity event types.
     */
    /**
     * Identity events raised by organization user sharing, and the properties they carry.
     */
    public static class UserSharingEvent {

        public static final String POST_SHARE_USER = "POST_SHARE_USER";
        public static final String POST_UNSHARE_USER = "POST_UNSHARE_USER";
        public static final String SHARED_USER_ID = "SHARED_USER_ID";
        public static final String SHARED_ORGANIZATION_ID = "SHARED_ORGANIZATION_ID";
        public static final String ASSOCIATED_USER_ID = "ASSOCIATED_USER_ID";
        public static final String ASSOCIATED_ORGANIZATION_ID = "ASSOCIATED_ORGANIZATION_ID";
        public static final String SHARED_TYPE = "SHARED_TYPE";
        // Thread-local flags user sharing sets while it creates or deletes the profile of a shared user.
        public static final String PROCESS_ADD_SHARED_USER = "processAddSharedUser";
        public static final String PROCESS_DELETE_SHARED_USER = "processDeleteSharedUser";

        private UserSharingEvent() {

        }
    }

    /**
     * Properties added to a role membership event when it is published once per affected user.
     */
    public static class UserRoleEvent {

        public static final String ROLE_MEMBER_USER_ID = "ROLE_MEMBER_USER_ID";
        public static final String ROLE_MEMBER_CHANGE = "ROLE_MEMBER_CHANGE";
        public static final String ADDED = "ADDED";
        public static final String REMOVED = "REMOVED";

        private UserRoleEvent() {

        }
    }

    public static class Event {

        public static final String LOGIN_SUCCESS_EVENT = "https://schemas.identity.wso2.org/events/login/event-type/loginSuccess";
        public static final String LOGIN_FAILURE_EVENT = "https://schemas.identity.wso2.org/events/login/event-type/loginFailed";
        public static final String POST_UPDATE_USER_CREDENTIAL = "https://schemas.identity.wso2.org/events/credential/event-type/credentialUpdated";
        public static final String POST_REGISTRATION_SUCCESS_EVENT = "https://schemas.identity.wso2.org/events/registration/event-type/registrationSuccess";
        public static final String POST_REGISTRATION_FAILED_EVENT = "https://schemas.identity.wso2.org/events/registration/event-type/registrationFailed";
        public static final String POST_USER_CREATED_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userCreated";
        public static final String POST_USER_SHARED_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userShared";
        public static final String POST_USER_UNSHARED_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userUnshared";
        public static final String POST_USER_ROLES_UPDATED_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userRolesUpdated";
        public static final String POST_UPDATE_USER_LIST_OF_ROLE_EVENT = "https://schemas.identity.wso2.org/events/group/event-type/groupUpdated";
        public static final String POST_DELETE_USER_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userDeleted";
        public static final String POST_UNLOCK_ACCOUNT_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userAccountUnlocked";
        public static final String POST_LOCK_ACCOUNT_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userAccountLocked";
        public static final String POST_USER_PROFILE_UPDATED_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userProfileUpdated";
        public static final String POST_ACCOUNT_ENABLE_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userEnabled";
        public static final String POST_ACCOUNT_DISABLE_EVENT = "https://schemas.identity.wso2.org/events/user/event-type/userDisabled";
        public static final String SESSION_CREATED_EVENT = "https://schemas.identity.wso2.org/events/session/event-type/sessionEstablished";
        public static final String SESSION_REVOKED_EVENT = "https://schemas.identity.wso2.org/events/session/event-type/sessionRevoked";
        public static final String SESSION_PRESENTED_EVENT = "https://schemas.identity.wso2.org/events/session/event-type/sessionPresented";
        public static final String TOKEN_ISSUED_EVENT = "https://schemas.identity.wso2.org/events/token/event-type/accessTokenIssued";
        public static final String TOKEN_REVOKED_EVENT = "https://schemas.identity.wso2.org/events/token/event-type/accessTokenRevoked";
        public static final String CONSENT_PURPOSE_VERSION_ADDED_EVENT =
                "https://schemas.identity.wso2.org/events/consent-purpose/event-type/purposeVersionAdded";
        public static final String CONSENT_ADDED_EVENT =
                "https://schemas.identity.wso2.org/events/consent/event-type/consentAdded";
        public static final String CONSENT_REVOKED_EVENT =
                "https://schemas.identity.wso2.org/events/consent/event-type/consentRevoked";
        public static final String ROLE_CREATED_EVENT =
                "https://schemas.identity.wso2.org/events/role/event-type/roleCreated";
        public static final String ROLE_META_UPDATED_EVENT =
                "https://schemas.identity.wso2.org/events/role/event-type/roleMetaUpdated";
        public static final String ROLE_DELETED_EVENT =
                "https://schemas.identity.wso2.org/events/role/event-type/roleDeleted";
        public static final String ROLE_USERS_UPDATED_EVENT =
                "https://schemas.identity.wso2.org/events/role/event-type/roleUsersUpdated";
        public static final String ROLE_GROUPS_UPDATED_EVENT =
                "https://schemas.identity.wso2.org/events/role/event-type/roleGroupsUpdated";
        public static final String ROLE_IDP_GROUPS_UPDATED_EVENT =
                "https://schemas.identity.wso2.org/events/role/event-type/roleIdpGroupsUpdated";
        public static final String ROLE_PERMISSIONS_UPDATED_EVENT =
                "https://schemas.identity.wso2.org/events/role/event-type/rolePermissionsUpdated";
        public static final String POST_ORGANIZATION_CREATED_EVENT =
                "https://schemas.identity.wso2.org/events/organization/event-type/organizationCreated";
        public static final String POST_ORGANIZATION_UPDATED_EVENT =
                "https://schemas.identity.wso2.org/events/organization/event-type/organizationUpdated";
        public static final String POST_ORGANIZATION_DELETED_EVENT =
                "https://schemas.identity.wso2.org/events/organization/event-type/organizationDeleted";
    }

    /**
     * This class represents role management event handler configuration keys.
     */
    public static class RoleManagement {

        public static final int ROLE_LIST_MAX_SIZE = 1000;

        private RoleManagement() {

        }
    }
}
