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

package org.wso2.identity.webhook.wso2.event.handler.internal.util;

import org.mockito.MockedStatic;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Common utility methods for tests.
 */
public class TestUtils {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final int SAMPLE_TENANT_ID = 100;
    private static MockedStatic<ServiceURLBuilder> mockedStaticServiceURLBuilder;
    private static MockedStatic<IdentityTenantUtil> mockedStaticIdentityTenantUtil;
    private static ServiceURLBuilder builder;

    public static void mockServiceURLBuilder() {

        builder = new ServiceURLBuilder() {
            String path = "/t/myorg";

            @Override
            public ServiceURLBuilder addPath(String... strings) {

                // A path that already carries the tenant or organization perspective is used as given, the way
                // the real builder leaves such a path unqualified.
                this.path = "";
                Arrays.stream(strings).forEach(x -> {
                    path += x;
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() {

                ServiceURL serviceURL = mock(ServiceURL.class);
                when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                when(serviceURL.getRelativePublicURL()).thenReturn(path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        mockedStaticServiceURLBuilder = mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(builder);
    }

    public static void closeMockedServiceURLBuilder() {

        mockedStaticServiceURLBuilder.close();
    }

    public static void mockIdentityTenantUtil() {

        mockedStaticIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(SAMPLE_TENANT_DOMAIN)).thenReturn(SAMPLE_TENANT_ID);
    }

    public static void closeMockedIdentityTenantUtil() {

        mockedStaticIdentityTenantUtil.close();
    }
}
