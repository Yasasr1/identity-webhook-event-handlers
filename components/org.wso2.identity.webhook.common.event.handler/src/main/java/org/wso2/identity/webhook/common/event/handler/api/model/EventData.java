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

package org.wso2.identity.webhook.common.event.handler.api.model;

import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * Event data model.
 */
public class EventData {

    private final String eventName;
    private final HttpServletRequest request;
    private final Map<String, Object> eventParams;
    private final AuthenticationContext authenticationContext;
    private final AuthenticatorStatus authenticatorStatus;
    private final AuthenticatedUser authenticatedUser;
    private final SessionContext sessionContext;
    private final String userId;
    private final String tenantDomain;
    private final Map<String, Object> properties;

    private EventData(Builder builder) {

        this.eventName = builder.eventName;
        this.request = builder.request;
        this.authenticationContext = builder.authenticationContext;
        this.authenticatorStatus = builder.authenticatorStatus;
        this.authenticatedUser = builder.authenticatedUser;
        this.sessionContext = builder.sessionContext;
        this.userId = builder.userId;
        this.tenantDomain = builder.tenantDomain;
        this.eventParams =
                builder.eventParams != null ? Collections.unmodifiableMap(builder.eventParams) : Collections.emptyMap();
        this.properties =
                builder.properties != null ? Collections.unmodifiableMap(builder.properties) : Collections.emptyMap();
    }

    public String getEventName() {

        return eventName;
    }

    public HttpServletRequest getRequest() {

        return request;
    }

    public Map<String, Object> getEventParams() {

        return eventParams;
    }

    public AuthenticationContext getAuthenticationContext() {

        return authenticationContext;
    }

    public AuthenticatorStatus getAuthenticatorStatus() {

        return authenticatorStatus;
    }

    public AuthenticatedUser getAuthenticatedUser() {

        return authenticatedUser;
    }

    public SessionContext getSessionContext() {

        return sessionContext;
    }

    public String getUserId() {

        return userId;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public Map<String, Object> getProperties() {

        return properties;
    }

    public static Builder builder() {

        return new Builder();
    }

    /**
     * Builder carrying the values of this event data, for deriving a copy with some of them changed.
     * <p>
     * The model is immutable, so a value resolved after the event data was built -- the organization a login was
     * performed in, for one -- is applied by deriving a new instance rather than by mutating this one.
     *
     * @return Builder holding the current values.
     */
    public Builder toBuilder() {

        return new Builder()
                .eventName(this.eventName)
                .request(this.request)
                .eventParams(this.eventParams)
                .authenticationContext(this.authenticationContext)
                .authenticatorStatus(this.authenticatorStatus)
                .authenticatedUser(this.authenticatedUser)
                .sessionContext(this.sessionContext)
                .userId(this.userId)
                .tenantDomain(this.tenantDomain)
                .properties(this.properties);
    }

    /**
     * Builder class to build EventData.
     */
    public static class Builder {

        private String eventName;
        private HttpServletRequest request;
        private Map<String, Object> eventParams;
        private AuthenticationContext authenticationContext;
        private AuthenticatorStatus authenticatorStatus;
        private AuthenticatedUser authenticatedUser;
        private SessionContext sessionContext;
        private String userId;
        private String tenantDomain;

        private Map<String, Object> properties;

        public Builder eventName(String eventName) {

            this.eventName = eventName;
            return this;
        }

        public Builder request(HttpServletRequest request) {

            this.request = request;
            return this;
        }

        public Builder eventParams(Map<String, Object> eventParams) {

            this.eventParams = eventParams;
            return this;
        }

        public Builder authenticationContext(AuthenticationContext authenticationContext) {

            this.authenticationContext = authenticationContext;
            return this;
        }

        public Builder authenticatorStatus(AuthenticatorStatus authenticatorStatus) {

            this.authenticatorStatus = authenticatorStatus;
            return this;
        }

        public Builder authenticatedUser(AuthenticatedUser authenticatedUser) {

            this.authenticatedUser = authenticatedUser;
            return this;
        }

        public Builder sessionContext(SessionContext sessionContext) {

            this.sessionContext = sessionContext;
            return this;
        }

        public Builder userId(String userId) {

            this.userId = userId;
            return this;
        }

        public Builder tenantDomain(String tenantDomain) {

            this.tenantDomain = tenantDomain;
            return this;
        }

        public Builder properties(Map<String, Object> properties) {

            this.properties = properties;
            return this;
        }

        public EventData build() {

            return new EventData(this);
        }
    }
}
