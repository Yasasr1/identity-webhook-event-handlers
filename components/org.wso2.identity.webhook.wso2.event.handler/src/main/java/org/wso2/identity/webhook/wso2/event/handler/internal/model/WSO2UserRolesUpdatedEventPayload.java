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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.RoleRef;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;

import java.util.List;

/**
 * Payload of roles added to, or removed from, a user.
 * <p>
 * {@code organization} is the organization the roles belong to. For a user shared with that organization,
 * {@code user} is the user in the organization it resides in and {@code sharedUser} its profile in
 * {@code organization}; for any other user, {@code user} is the user itself and {@code sharedUser} is absent.
 */
public class WSO2UserRolesUpdatedEventPayload extends WSO2BaseEventPayload {

    private final User sharedUser;
    private final List<RoleRef> addedRoles;
    private final List<RoleRef> removedRoles;

    private WSO2UserRolesUpdatedEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.action = builder.action;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.user = builder.user;
        this.sharedUser = builder.sharedUser;
        this.addedRoles = builder.addedRoles;
        this.removedRoles = builder.removedRoles;
    }

    public User getSharedUser() {

        return sharedUser;
    }

    public List<RoleRef> getAddedRoles() {

        return addedRoles;
    }

    public List<RoleRef> getRemovedRoles() {

        return removedRoles;
    }

    /**
     * Builder of {@link WSO2UserRolesUpdatedEventPayload}.
     */
    public static class Builder {

        private String initiatorType;
        private String initiatorIpAddress;
        private String action;
        private Tenant tenant;
        private Organization organization;
        private User user;
        private User sharedUser;
        private List<RoleRef> addedRoles;
        private List<RoleRef> removedRoles;

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

        public Builder sharedUser(User sharedUser) {

            this.sharedUser = sharedUser;
            return this;
        }

        public Builder addedRoles(List<RoleRef> addedRoles) {

            this.addedRoles = addedRoles;
            return this;
        }

        public Builder removedRoles(List<RoleRef> removedRoles) {

            this.removedRoles = removedRoles;
            return this;
        }

        public WSO2UserRolesUpdatedEventPayload build() {

            return new WSO2UserRolesUpdatedEventPayload(this);
        }
    }
}
