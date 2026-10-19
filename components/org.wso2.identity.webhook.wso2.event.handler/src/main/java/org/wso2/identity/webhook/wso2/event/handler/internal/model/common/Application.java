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

/**
 * Application class.
 */
public class Application {

    private String id;
    private String name;
    private String consumerKey;
    private Organization organization;

    public String getId() {

        return id;
    }

    public String getName() {

        return name;
    }

    public String getConsumerKey() {

        return consumerKey;
    }

    public Organization getOrganization() {

        return organization;
    }

    private Application(Builder builder) {

        this.id = builder.id;
        this.name = builder.name;
        this.consumerKey = builder.consumerKey;
        this.organization = builder.organization;
    }

    /**
     * Builder for the Application class.
     */
    public static class Builder {

        private String id;
        private String name;
        private String consumerKey;
        private Organization organization;

        public Builder id(String id) {

            this.id = id;
            return this;
        }

        public Builder name(String name) {

            this.name = name;
            return this;
        }

        public Builder consumerKey(String consumerKey) {

            this.consumerKey = consumerKey;
            return this;
        }

        public Builder organization(Organization organization) {

            if (organization != null) {
                this.organization = organization;
            }
            return this;
        }

        public Application build() {

            return new Application(this);
        }
    }
}
