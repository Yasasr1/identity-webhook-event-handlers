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

package org.wso2.identity.webhook.wso2.event.handler.internal.model.common;

import java.util.ArrayList;
import java.util.List;

/**
 * User class.
 */
public class User {

    private String id;
    private List<UserClaim> claims;
    private Organization organization;
    private String ref;
    private List<String> groups = new ArrayList<>();
    private List<String> roles = new ArrayList<>();
    private List<UserClaim> additionalClaims;
    private List<UserClaim> addedClaims;
    private List<UserClaim> updatedClaims;
    private List<UserClaim> removedClaims;
    private SharedUserProfile sharedUserProfile;

    public List<String> getGroups() {

        return groups;
    }

    public void setGroups(List<String> groups) {

        this.groups = groups;
    }

    /**
     * Get the organization of the user.
     *
     * @return Organization of the user.
     */
    public Organization getOrganization() {

        return organization;
    }

    /**
     * Set the organization of the user.
     *
     * @param organization Organization of the user.
     */
    public void setOrganization(Organization organization) {

        this.organization = organization;
    }

    public void addGroup(String group) {

        this.groups.add(group);
    }

    public List<String> getRoles() {

        return roles;
    }

    public void setRoles(List<String> roles) {

        this.roles = roles;
    }

    public void addRole(String role) {

        this.roles.add(role);
    }

    public String getId() {

        return id;
    }

    public void setId(String id) {

        this.id = id;
    }

    public List<UserClaim> getClaims() {

        return claims;
    }

    public void setClaims(List<UserClaim> claims) {

        this.claims = claims;
    }

    public String getRef() {

        return ref;
    }

    public void setRef(String ref) {

        this.ref = ref;
    }

    public List<UserClaim> getRemovedClaims() {

        return removedClaims;
    }

    public void setRemovedClaims(
            List<UserClaim> removedClaims) {

        this.removedClaims = removedClaims;
    }

    public List<UserClaim> getUpdatedClaims() {

        return updatedClaims;
    }

    public void setUpdatedClaims(
            List<UserClaim> updatedClaims) {

        this.updatedClaims = updatedClaims;
    }

    public List<UserClaim> getAddedClaims() {

        return addedClaims;
    }

    public void setAddedClaims(
            List<UserClaim> addedClaims) {

        this.addedClaims = addedClaims;
    }

    public List<UserClaim> getAdditionalClaims() {

        return additionalClaims;
    }

    public void setAdditionalClaims(
            List<UserClaim> additionalClaims) {

        this.additionalClaims = additionalClaims;
    }

    public void addClaim(UserClaim claim) {

        if (claim != null) {
            if (this.claims == null) {
                this.claims = new ArrayList<>();
            }
            this.claims.add(claim);
        }
    }

    public SharedUserProfile getSharedUserProfile() {

        return sharedUserProfile;
    }

    public void setSharedUserProfile(SharedUserProfile sharedUserProfile) {

        this.sharedUserProfile = sharedUserProfile;
    }
}
