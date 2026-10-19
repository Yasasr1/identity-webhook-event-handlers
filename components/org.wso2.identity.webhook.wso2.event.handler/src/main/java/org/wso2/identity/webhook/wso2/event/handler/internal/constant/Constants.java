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

package org.wso2.identity.webhook.wso2.event.handler.internal.constant;

/**
 * Constants class.
 */
public class Constants {

    public static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";
    public static final String IDENTITY_PROVIDER_MAPPED_USER_ROLES = "identityProviderMappedUserRoles";
    public static final String USER_ORGANIZATION = "user_organization";
    public static final String CURRENT_AUTHENTICATOR_ERROR_CODE = "currentAuthenticatorErrorCode";
    public static final String CURRENT_AUTHENTICATOR_ERROR_MESSAGE = "currentAuthenticatorErrorMessage";
    public static final String AUTHENTICATION_ERROR_MESSAGE = "authenticationErrorMessage";
    public static final String DATA_MAP = "dataMap";
    public static final String ORGANIZATION_AUTHENTICATOR = "OrganizationAuthenticator";
    public static final String SCIM2_USERS_ENDPOINT = "/scim2/Users";
    public static final String SCIM2_ROLES_ENDPOINT = "/scim2/v2/Roles";
    public static final String ORGANIZATIONS_API_ENDPOINT = "/api/server/v1/organizations";
    public static final String CONSOLE_APP_CONSUMER_KEY = "CONSOLE";

    /**
     * Event property carrying the identifier of the user's profile in the organization it is accessing, which a
     * user shared into that organization has in addition to the one it has where it resides.
     */
    public static final String SHARED_USER_ID = "SHARED_USER_ID";
    public static final String CONSOLE_APP_NAME = "Console";

    public static final String GROUPS_CLAIM = "http://wso2.org/claims/groups";
    public static final String FIRST_NAME_CLAIM_URI = "http://wso2.org/claims/givenname";
    public static final String LAST_NAME_CLAIM_URI = "http://wso2.org/claims/lastname";
    public static final String CREATED_CLAIM = "http://wso2.org/claims/created";
    public static final String MODIFIED_CLAIM = "http://wso2.org/claims/modified";
    public static final String RESOURCE_TYPE_CLAIM = "http://wso2.org/claims/resourceType";
    public static final String LOCATION_CLAIM = "http://wso2.org/claims/location";
    public static final String USERNAME_CLAIM_URI = "http://wso2.org/claims/username";
    public static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    public static final String WSO2_CLAIM_URI_PREFIX = "http://wso2.org/claims/";
    public static final String AGENT_NAME_CLAIM_URI = "http://wso2.org/claims/agent/Name";
}
