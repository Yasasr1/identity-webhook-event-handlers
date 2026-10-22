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

package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.TargetOrganization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;

/**
 * Payload of a user shared with, or unshared from, an organization.
 * <p>
 * {@code organization} is the organization the operation was performed in, {@code user} the shared user in the
 * organization it resides in, {@code targetOrganization} the organization the user was shared with or unshared from,
 * and {@code sharedUser} the profile of the user in that organization.
 */
public class WSO2UserSharingEventPayload extends WSO2BaseEventPayload {

    private final TargetOrganization targetOrganization;
    private final User sharedUser;
    private final String sharedType;

    private WSO2UserSharingEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.action = builder.action;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.user = builder.user;
        this.targetOrganization = builder.targetOrganization;
        this.sharedUser = builder.sharedUser;
        this.sharedType = builder.sharedType;
    }

    public TargetOrganization getTargetOrganization() {

        return targetOrganization;
    }

    public User getSharedUser() {

        return sharedUser;
    }

    public String getSharedType() {

        return sharedType;
    }

    /**
     * Builder of {@link WSO2UserSharingEventPayload}.
     */
    public static class Builder {

        private String initiatorType;
        private String initiatorIpAddress;
        private String action;
        private Tenant tenant;
        private Organization organization;
        private User user;
        private TargetOrganization targetOrganization;
        private User sharedUser;
        private String sharedType;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder initiatorIpAddress(String initiatorIpAddress) {

            this.initiatorIpAddress = initiatorIpAddress;
            return this;
        }

        public Builder action(String action) {

            this.action = action;
            return this;
        }

        public Builder tenant(Tenant tenant) {

            this.tenant = tenant;
            return this;
        }

        public Builder organization(Organization organization) {

            this.organization = organization;
            return this;
        }

        public Builder user(User user) {

            this.user = user;
            return this;
        }

        public Builder targetOrganization(TargetOrganization targetOrganization) {

            this.targetOrganization = targetOrganization;
            return this;
        }

        public Builder sharedUser(User sharedUser) {

            this.sharedUser = sharedUser;
            return this;
        }

        public Builder sharedType(String sharedType) {

            this.sharedType = sharedType;
            return this;
        }

        public WSO2UserSharingEventPayload build() {

            return new WSO2UserSharingEventPayload(this);
        }
    }
}
