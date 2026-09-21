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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.webhook.common.event.handler.api.builder.RoleManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for {@link RoleManagementEventHookHandler}.
 */
public class RoleManagementEventHookHandlerTest {

    private static final String ROLE_CHANNEL_URI = "https://schemas.identity.wso2.org/events/role";
    private static final String ROLE_CREATED_EVENT_URI =
            "https://schemas.identity.wso2.org/events/role/event-type/roleCreated";
    private static final String CARBON_SUPER = "carbon.super";
    private static final String SUB_ORG_TENANT = "sub-org-tenant";

    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private RoleManagementEventPayloadBuilder mockedRoleManagementEventPayloadBuilder;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private RoleManagementEventHookHandler roleManagementEventHookHandler;

    @BeforeClass
    public void setupClass() throws IdentityEventException {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        roleManagementEventHookHandler = new RoleManagementEventHookHandler();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    @AfterMethod
    public void tearDownMethod() {

        Mockito.reset(mockedEventPublisherService);
    }

    @Test
    public void testGetName() {

        assertEquals(roleManagementEventHookHandler.getName(), Constants.ROLE_MANAGEMENT_EVENT_HOOK_NAME);
    }

    @DataProvider(name = "supportedEventsDataProvider")
    public Object[][] supportedEventsDataProvider() {

        return new Object[][]{
                {IdentityEventConstants.Event.POST_ADD_ROLE_V2_EVENT},
                {IdentityEventConstants.Event.POST_UPDATE_ROLE_V2_NAME_EVENT},
                {IdentityEventConstants.Event.POST_DELETE_ROLE_V2_EVENT},
                {IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE_V2_EVENT},
                {IdentityEventConstants.Event.POST_UPDATE_GROUP_LIST_OF_ROLE_V2_EVENT},
                {IdentityEventConstants.Event.POST_UPDATE_IDP_GROUP_LIST_OF_ROLE_V2_EVENT},
                {IdentityEventConstants.Event.POST_UPDATE_PERMISSIONS_FOR_ROLE_V2_EVENT}
        };
    }

    @Test(dataProvider = "supportedEventsDataProvider")
    public void testCanHandleSupportedEvents(String eventName) {

        Event event = new Event(eventName);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);

        assertTrue(roleManagementEventHookHandler.canHandle(messageContext),
                "Handler should be able to handle event: " + eventName);
    }

    @DataProvider(name = "unsupportedEventsDataProvider")
    public Object[][] unsupportedEventsDataProvider() {

        return new Object[][]{
                {IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE_EVENT},
                {IdentityEventConstants.Event.POST_ADD_ROLE_EVENT},
                {IdentityEventConstants.Event.PRE_DELETE_ROLE_V2_EVENT},
                {IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT},
                {IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL}
        };
    }

    @Test(dataProvider = "unsupportedEventsDataProvider")
    public void testCannotHandleUnsupportedEvents(String eventName) {

        Event event = new Event(eventName);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertFalse(roleManagementEventHookHandler.canHandle(messageContext),
                "Handler should NOT be able to handle event: " + eventName);
    }

    @Test
    public void testHandleRoleCreatedEvent() throws Exception {

        Event event = createEventWithProperties(IdentityEventConstants.Event.POST_ADD_ROLE_V2_EVENT);

        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        "roleCreated", "Role created event", ROLE_CREATED_EVENT_URI);
        Channel channel = new Channel("Role Management", "Role Management Channel", ROLE_CHANNEL_URI,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));

        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getRoleManagementEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2))
                    .thenReturn(mockedRoleManagementEventPayloadBuilder);

            when(mockedRoleManagementEventPayloadBuilder.buildRoleCreatedEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventData eventData = mock(EventData.class);
                EventMetadata eventMetadata = mock(EventMetadata.class);
                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                when(eventData.getTenantDomain()).thenReturn(CARBON_SUPER);
                when(eventMetadata.getChannel()).thenReturn(ROLE_CHANNEL_URI);
                when(eventMetadata.getEvent()).thenReturn(ROLE_CREATED_EVENT_URI);
                when(eventMetadata.getEventProfile()).thenReturn("WSO2");

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                roleManagementEventHookHandler.handleEvent(event);

                verify(mockedEventPublisherService, times(1))
                        .publish(eq(tokenPayload), argThat(ctx ->
                                ctx.getTenantDomain().equals(CARBON_SUPER) &&
                                        ctx.getEventUri().equals(ROLE_CHANNEL_URI) &&
                                        ctx.getEventProfileName().equals("WSO2")
                        ));
            }
        }
    }

    @Test(dataProvider = "unsupportedEventsDataProvider")
    public void testCannotHandleUnsupportedEventsInSubOrganizationContext(String eventName) {

        Event event = new Event(eventName);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);

        try (MockedStatic<IdentityContext> identityContextMock = mockStatic(IdentityContext.class);
             MockedStatic<OrganizationManagementUtil> orgUtilMock = mockStatic(OrganizationManagementUtil.class)) {
            IdentityContext subOrgCtx = mock(IdentityContext.class);
            when(subOrgCtx.getTenantDomain()).thenReturn(SUB_ORG_TENANT);
            identityContextMock.when(IdentityContext::getThreadLocalIdentityContext).thenReturn(subOrgCtx);
            orgUtilMock.when(() -> OrganizationManagementUtil.isOrganization(SUB_ORG_TENANT)).thenReturn(true);

            assertFalse(roleManagementEventHookHandler.canHandle(messageContext),
                    "Event type gating should still apply in a sub-organization context: " + eventName);
        }
    }

    @Test
    public void testCanHandleDoesNotDependOnIdentityContext() {

        Event event = new Event(IdentityEventConstants.Event.POST_ADD_ROLE_V2_EVENT);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);

        try (MockedStatic<IdentityContext> identityContextMock = mockStatic(IdentityContext.class)) {
            identityContextMock.when(IdentityContext::getThreadLocalIdentityContext).thenReturn(null);

            assertTrue(roleManagementEventHookHandler.canHandle(messageContext),
                    "canHandle should return true even when no IdentityContext is available " +
                            "(async worker thread with no context propagation).");
            identityContextMock.verifyNoInteractions();
        }
    }

    @Test
    public void testCanHandleReturnsFalseWhenEventNameIsNull() {

        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(new Event(null));
        assertFalse(roleManagementEventHookHandler.canHandle(messageContext),
                "canHandle should return false when the event name is null.");
    }

    @Test
    public void testHandleEventWithNoProfiles() throws Exception {

        Event event = createEventWithProperties(IdentityEventConstants.Event.POST_ADD_ROLE_V2_EVENT);
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.emptyList());
        roleManagementEventHookHandler.handleEvent(event);
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
        properties.put(IdentityEventConstants.EventProperty.ROLE_ID, "test-role-id");
        return new Event(eventName, properties);
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedRoleManagementEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2);
        when(mockedRoleManagementEventPayloadBuilder.buildRoleCreatedEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        EventHookHandlerDataHolder.getInstance().addRoleManagementEventPayloadBuilder(
                mockedRoleManagementEventPayloadBuilder);
    }
}
