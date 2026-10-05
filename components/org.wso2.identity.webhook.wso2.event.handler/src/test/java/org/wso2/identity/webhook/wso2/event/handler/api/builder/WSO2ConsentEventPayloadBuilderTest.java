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

package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.consent.mgt.core.ConsentManager;
import org.wso2.carbon.consent.mgt.core.exception.ConsentManagementException;
import org.wso2.carbon.consent.mgt.core.model.ConsentPurpose;
import org.wso2.carbon.consent.mgt.core.model.PIICategory;
import org.wso2.carbon.consent.mgt.core.model.PIICategoryValidity;
import org.wso2.carbon.consent.mgt.core.model.Receipt;
import org.wso2.carbon.consent.mgt.core.model.ReceiptInput;
import org.wso2.carbon.consent.mgt.core.model.ReceiptPurposeInput;
import org.wso2.carbon.consent.mgt.core.model.ReceiptService;
import org.wso2.carbon.consent.mgt.core.model.ReceiptServiceInput;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.core.context.util.IdentityContextUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2ConsentAddedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2ConsentRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import org.wso2.carbon.consent.mgt.core.constant.ConsentConstants;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_AUTHORIZE_CONSENT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for {@link WSO2ConsentEventPayloadBuilder}.
 */
public class WSO2ConsentEventPayloadBuilderTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = 100;
    private static final String ORG_ID = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String ORG_NAME = "myorg";
    private static final String ORG_HANDLE = "myorg";
    private static final String RECEIPT_ID = "d4f1a2b3-c5e6-7890-1234-abcdef567890";
    private static final String SERVICE_ID = "HealthTracker";
    private static final String SUBJECT_ID = "john.doe@myorg.com";
    private static final String PURPOSE_UUID = "f83aa1a3-5d4d-4c0e-84db-c3a4f1e6c8b2";
    private static final String PURPOSE_NAME = "Marketing Communications";
    private static final String PURPOSE_VERSION = "v2";
    private static final int PURPOSE_ID_INT = 42;
    private static final String CLAIM_URI_1 = "http://wso2.org/claims/emailaddress";
    private static final String CLAIM_URI_2 = "http://wso2.org/claims/dob";
    private static final String SAMPLE_INITIATOR_IP = "10.0.0.5";
    private static final String USER_NAME = "john.doe";
    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String SUB_ORG_TENANT_DOMAIN = "myorg.sub";

    @Mock
    private ConsentManager consentManager;

    private MockedStatic<IdentityContextUtil> identityContextUtil;
    private WSO2ConsentEventPayloadBuilder builder;

    @BeforeClass
    public void setUp() throws Exception {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);

        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setConsentManager(consentManager);

        mockServiceURLBuilder();
        mockIdentityTenantUtil();

        CommonTestUtils.initPrivilegedCarbonContext();

        identityContextUtil = mockStatic(IdentityContextUtil.class);
        identityContextUtil.when(IdentityContextUtil::getClientIpAddress).thenReturn(SAMPLE_INITIATOR_IP);

        RootOrganization rootOrganization = new RootOrganization.Builder()
                .associatedTenantId(TENANT_ID)
                .associatedTenantDomain(TENANT_DOMAIN)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setRootOrganization(rootOrganization);

        Organization organization = new Organization.Builder()
                .id(ORG_ID)
                .name(ORG_NAME)
                .organizationHandle(ORG_HANDLE)
                .depth(0)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setOrganization(organization);

        Flow flow = new Flow.Builder()
                .name(Flow.Name.LOGIN)
                .initiatingPersona(Flow.InitiatingPersona.USER)
                .build();
        IdentityContext.getThreadLocalIdentityContext().enterFlow(flow);

        builder = new WSO2ConsentEventPayloadBuilder();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        Mockito.reset(consentManager);
        if (identityContextUtil != null) {
            identityContextUtil.close();
        }
        IdentityContext.destroyCurrentContext();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @Test
    public void testGetEventSchemaType() {

        assertEquals(builder.getEventSchemaType(), Constants.EventSchema.WSO2);
    }

    @Test
    public void testBuildConsentAddedEvent_singlePurpose()
            throws IdentityEventException, ConsentManagementException {

        ReceiptInput receiptInput = new ReceiptInput();
        receiptInput.setConsentReceiptId(RECEIPT_ID);
        receiptInput.setPiiPrincipalId(SUBJECT_ID);
        receiptInput.setState("ACTIVE");
        receiptInput.setCollectionMethod("V2");

        PIICategoryValidity cat1 = new PIICategoryValidity(1, "INDEFINITE", true);
        PIICategoryValidity cat2 = new PIICategoryValidity(2, "INDEFINITE", true);

        PIICategory piiCat1 = mock(PIICategory.class);
        when(piiCat1.getName()).thenReturn(CLAIM_URI_1);
        PIICategory piiCat2 = mock(PIICategory.class);
        when(piiCat2.getName()).thenReturn(CLAIM_URI_2);
        when(consentManager.getPIICategory(1)).thenReturn(piiCat1);
        when(consentManager.getPIICategory(2)).thenReturn(piiCat2);

        ReceiptPurposeInput purposeInput = new ReceiptPurposeInput();
        purposeInput.setPurposeId(PURPOSE_ID_INT);
        purposeInput.setPurposeUuid(PURPOSE_UUID);
        purposeInput.setPurposeName(PURPOSE_NAME);
        purposeInput.setPurposeVersionId(PURPOSE_VERSION);
        purposeInput.setPiiCategory(Arrays.asList(cat1, cat2));

        ReceiptServiceInput serviceInput = new ReceiptServiceInput();
        serviceInput.setService(SERVICE_ID);
        serviceInput.setPurposes(Collections.singletonList(purposeInput));

        receiptInput.setServices(Collections.singletonList(serviceInput));

        EventData eventData = mock(EventData.class);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_INPUT, receiptInput);
        params.put(IdentityEventConstants.EventProperty.USER_NAME, USER_NAME);
        params.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, USER_STORE_DOMAIN);
        when(eventData.getEventParams()).thenReturn(params);

        List<EventPayload> payloads = builder.buildConsentAddedEvent(eventData);

        assertEquals(payloads.size(), 1);
        assertTrue(payloads.get(0) instanceof WSO2ConsentAddedEventPayload);

        WSO2ConsentAddedEventPayload payload = (WSO2ConsentAddedEventPayload) payloads.get(0);
        assertEquals(payload.getInitiatorType(), Flow.InitiatingPersona.USER.name());
        assertEquals(payload.getInitiatorIpAddress(), SAMPLE_INITIATOR_IP);

        assertNotNull(payload.getTenant());
        assertEquals(payload.getTenant().getName(), TENANT_DOMAIN);
        assertEquals(payload.getTenant().getId(), String.valueOf(TENANT_ID));

        assertNotNull(payload.getConsent());
        assertEquals(payload.getConsent().getId(), RECEIPT_ID);
        assertEquals(payload.getConsent().getState(), "ACTIVE");
        assertEquals(payload.getConsent().getServiceId(), SERVICE_ID);

        assertNotNull(payload.getConsent().getPurpose());
        assertEquals(payload.getConsent().getPurpose().getId(), PURPOSE_UUID);
        assertEquals(payload.getConsent().getPurpose().getName(), PURPOSE_NAME);
        assertEquals(payload.getConsent().getPurpose().getVersion(), PURPOSE_VERSION);

        assertNotNull(payload.getConsent().getPurpose().getElements());
        assertEquals(payload.getConsent().getPurpose().getElements().size(), 2);
        assertEquals(payload.getConsent().getPurpose().getElements().get(0).getName(), CLAIM_URI_1);
        assertEquals(payload.getConsent().getPurpose().getElements().get(1).getName(), CLAIM_URI_2);
    }

    @Test
    public void testBuildConsentAddedEvent_multiPurposeFanOut() throws IdentityEventException {

        ReceiptInput receiptInput = new ReceiptInput();
        receiptInput.setConsentReceiptId(RECEIPT_ID);
        receiptInput.setPiiPrincipalId(SUBJECT_ID);
        receiptInput.setState("ACTIVE");
        receiptInput.setCollectionMethod("V2");

        ReceiptPurposeInput p1 = new ReceiptPurposeInput();
        p1.setPurposeId(1);
        p1.setPurposeName("Purpose One");
        p1.setPurposeVersionId("v1");
        p1.setPiiCategory(Collections.emptyList());

        ReceiptPurposeInput p2 = new ReceiptPurposeInput();
        p2.setPurposeId(2);
        p2.setPurposeName("Purpose Two");
        p2.setPurposeVersionId("v1");
        p2.setPiiCategory(Collections.emptyList());

        ReceiptPurposeInput p3 = new ReceiptPurposeInput();
        p3.setPurposeId(3);
        p3.setPurposeName("Purpose Three");
        p3.setPurposeVersionId("v2");
        p3.setPiiCategory(Collections.emptyList());

        ReceiptServiceInput serviceInput = new ReceiptServiceInput();
        serviceInput.setService(SERVICE_ID);
        serviceInput.setPurposes(Arrays.asList(p1, p2, p3));

        receiptInput.setServices(Collections.singletonList(serviceInput));

        EventData eventData = mock(EventData.class);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_INPUT, receiptInput);
        params.put(IdentityEventConstants.EventProperty.USER_NAME, USER_NAME);
        params.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, USER_STORE_DOMAIN);
        when(eventData.getEventParams()).thenReturn(params);

        List<EventPayload> payloads = builder.buildConsentAddedEvent(eventData);

        assertEquals(payloads.size(), 3);
        List<String> purposeNames = Arrays.asList(
                ((WSO2ConsentAddedEventPayload) payloads.get(0)).getConsent().getPurpose().getName(),
                ((WSO2ConsentAddedEventPayload) payloads.get(1)).getConsent().getPurpose().getName(),
                ((WSO2ConsentAddedEventPayload) payloads.get(2)).getConsent().getPurpose().getName()
        );
        assertTrue(purposeNames.contains("Purpose One"));
        assertTrue(purposeNames.contains("Purpose Two"));
        assertTrue(purposeNames.contains("Purpose Three"));
    }

    @Test
    public void testBuildConsentAddedEvent_rejectedStateIsSkipped() throws IdentityEventException {

        ReceiptInput receiptInput = new ReceiptInput();
        receiptInput.setConsentReceiptId(RECEIPT_ID);
        receiptInput.setPiiPrincipalId(SUBJECT_ID);
        receiptInput.setState("REJECTED");
        receiptInput.setCollectionMethod("V2");

        EventData eventData = mock(EventData.class);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_INPUT, receiptInput);
        params.put(IdentityEventConstants.EventProperty.USER_NAME, USER_NAME);
        params.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, USER_STORE_DOMAIN);
        when(eventData.getEventParams()).thenReturn(params);

        List<EventPayload> payloads = builder.buildConsentAddedEvent(eventData);

        assertTrue(payloads.isEmpty());
    }

    @Test
    public void testBuildConsentAddedEvent_nullReceiptInput() throws IdentityEventException {

        EventData eventData = mock(EventData.class);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_INPUT, null);
        when(eventData.getEventParams()).thenReturn(params);

        List<EventPayload> payloads = builder.buildConsentAddedEvent(eventData);

        assertTrue(payloads.isEmpty());
    }

    @Test
    public void testBuildConsentAddedEvent_fromAuthorization_singlePurpose()
            throws Exception {

        Receipt receipt = mock(Receipt.class);
        ReceiptService receiptService = mock(ReceiptService.class);
        org.wso2.carbon.consent.mgt.core.model.ConsentPurpose consentPurpose =
                mock(org.wso2.carbon.consent.mgt.core.model.ConsentPurpose.class);

        PIICategoryValidity cat = new PIICategoryValidity(1, "INDEFINITE", true);
        PIICategory piiCat = mock(PIICategory.class);
        when(piiCat.getName()).thenReturn(CLAIM_URI_1);
        when(consentManager.getPIICategory(1)).thenReturn(piiCat);

        when(consentPurpose.getUuid()).thenReturn(PURPOSE_UUID);
        when(consentPurpose.getPurpose()).thenReturn(PURPOSE_NAME);
        when(consentPurpose.getPurposeVersionId()).thenReturn(PURPOSE_VERSION);
        when(consentPurpose.getPiiCategory()).thenReturn(Collections.singletonList(cat));

        when(receiptService.getService()).thenReturn(SERVICE_ID);
        when(receiptService.getPurposes()).thenReturn(Collections.singletonList(consentPurpose));
        when(receipt.getServices()).thenReturn(Collections.singletonList(receiptService));
        doReturn(receipt).when(consentManager).getReceiptWithExtendedSchema(RECEIPT_ID);

        EventData eventData = mock(EventData.class);
        when(eventData.getEventName()).thenReturn(POST_AUTHORIZE_CONSENT);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_ID, RECEIPT_ID);
        params.put(IdentityEventConstants.EventProperty.USER_ID, SUBJECT_ID);
        params.put(ConsentConstants.AUTHZ_STATUS, "APPROVED");
        params.put(IdentityEventConstants.EventProperty.USER_NAME, USER_NAME);
        params.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, USER_STORE_DOMAIN);
        when(eventData.getEventParams()).thenReturn(params);

        List<EventPayload> payloads = builder.buildConsentAddedEvent(eventData);

        assertEquals(payloads.size(), 1);
        assertTrue(payloads.get(0) instanceof WSO2ConsentAddedEventPayload);

        WSO2ConsentAddedEventPayload payload = (WSO2ConsentAddedEventPayload) payloads.get(0);
        assertNotNull(payload.getConsent());
        assertEquals(payload.getConsent().getId(), RECEIPT_ID);
        assertEquals(payload.getConsent().getState(), "APPROVED");
        assertEquals(payload.getConsent().getServiceId(), SERVICE_ID);
        assertNotNull(payload.getConsent().getPurpose());
        assertEquals(payload.getConsent().getPurpose().getId(), PURPOSE_UUID);
        assertEquals(payload.getConsent().getPurpose().getName(), PURPOSE_NAME);
        assertEquals(payload.getConsent().getPurpose().getVersion(), PURPOSE_VERSION);
        assertNotNull(payload.getConsent().getPurpose().getElements());
        assertEquals(payload.getConsent().getPurpose().getElements().get(0).getName(), CLAIM_URI_1);
    }

    @Test
    public void testBuildConsentAddedEvent_fromAuthorization_nullReceiptId() throws IdentityEventException {

        EventData eventData = mock(EventData.class);
        when(eventData.getEventName()).thenReturn(POST_AUTHORIZE_CONSENT);
        Map<String, Object> params = new HashMap<>();
        when(eventData.getEventParams()).thenReturn(params);

        List<EventPayload> payloads = builder.buildConsentAddedEvent(eventData);

        assertTrue(payloads.isEmpty());
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testBuildConsentAddedEvent_fromAuthorization_consentManagerException()
            throws Exception {

        when(consentManager.getReceiptWithExtendedSchema(RECEIPT_ID))
                .thenThrow(new ConsentManagementException("CONSENT-60001", "Receipt not found"));

        EventData eventData = mock(EventData.class);
        when(eventData.getEventName()).thenReturn(POST_AUTHORIZE_CONSENT);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_ID, RECEIPT_ID);
        params.put(IdentityEventConstants.EventProperty.USER_ID, SUBJECT_ID);
        params.put(ConsentConstants.AUTHZ_STATUS, "APPROVED");
        params.put(IdentityEventConstants.EventProperty.USER_NAME, USER_NAME);
        params.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, USER_STORE_DOMAIN);
        when(eventData.getEventParams()).thenReturn(params);

        builder.buildConsentAddedEvent(eventData);
    }

    /**
     * Verifies that a consent added through the receipt path reads the user from the tenant the
     * event carries, rather than from the root tenant of the hierarchy.
     * <p>
     * {@code resolveTenant()} names the root organization, which is what the payload's tenant block
     * reports. The user, though, lives in the organization the consent was given in, and for a sub
     * organization that is a different tenant. Reading the user from the root tenant there resolves
     * the wrong user, or none at all.
     * <p>
     * The tenant domain reaches {@link WSO2PayloadUtils#buildUser(String, String, String)} and
     * nothing else, and that method returns an empty {@link User} when no realm is available, so
     * the argument cannot be observed from the payload. It is stubbed on a static mock and asserted
     * directly. {@link Answers#CALLS_REAL_METHODS} keeps every other {@code WSO2PayloadUtils}
     * helper the builder relies on behaving normally.
     * <p>
     * The tenant block is asserted too, to pin that this affects only the user lookup: an event
     * raised in a sub organization is still reported as belonging to the root tenant.
     */
    @Test
    public void testAddedEventUsesEventTenant() throws Exception {

        EventData eventData = mock(EventData.class);
        when(eventData.getEventParams()).thenReturn(buildReceiptInputParams());
        when(eventData.getTenantDomain()).thenReturn(SUB_ORG_TENANT_DOMAIN);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Answers.CALLS_REAL_METHODS)) {
            payloadUtils.when(() -> WSO2PayloadUtils.buildUser(anyString(), anyString(), anyString()))
                    .thenReturn(new User());

            List<EventPayload> payloads = builder.buildConsentAddedEvent(eventData);

            assertEquals(payloads.size(), 1);
            payloadUtils.verify(() -> WSO2PayloadUtils.buildUser(USER_STORE_DOMAIN, SUBJECT_ID,
                    SUB_ORG_TENANT_DOMAIN));

            WSO2ConsentAddedEventPayload payload = (WSO2ConsentAddedEventPayload) payloads.get(0);
            assertEquals(payload.getTenant().getName(), TENANT_DOMAIN);
            assertEquals(payload.getTenant().getId(), String.valueOf(TENANT_ID));
        }
    }

    /**
     * Verifies that an empty tenant domain on the event is ignored in favour of the root tenant.
     * <p>
     * This is the case the {@code StringUtils.isNotEmpty} guard exists for. An event that carries no
     * tenant is the ordinary root-organization flow; were the empty value preferred, the user would
     * be looked up in no tenant at all and the payload would carry an empty user. A null tenant
     * domain takes the same branch, and is covered by
     * {@link #testRevokedEventFallsBackToRootTenant()}.
     *
     * @see #testAddedEventUsesEventTenant() for why the argument is asserted on a static mock.
     */
    @Test
    public void testAddedEventFallsBackToRootTenant() throws Exception {

        EventData eventData = mock(EventData.class);
        when(eventData.getEventParams()).thenReturn(buildReceiptInputParams());
        when(eventData.getTenantDomain()).thenReturn("");

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Answers.CALLS_REAL_METHODS)) {
            payloadUtils.when(() -> WSO2PayloadUtils.buildUser(anyString(), anyString(), anyString()))
                    .thenReturn(new User());

            List<EventPayload> payloads = builder.buildConsentAddedEvent(eventData);

            assertEquals(payloads.size(), 1);
            payloadUtils.verify(() -> WSO2PayloadUtils.buildUser(USER_STORE_DOMAIN, SUBJECT_ID,
                    TENANT_DOMAIN));
        }
    }

    /**
     * Verifies that a revoked consent reads the user from the tenant the event carries.
     * <p>
     * The revocation path resolves its subject from the stored receipt rather than from the event
     * parameters, so it reaches {@code buildUser} by a route of its own and needs covering
     * separately from the added-consent path.
     * <p>
     * The consent fields are asserted alongside the tenant because this is also the first coverage
     * of {@code buildConsentRevokedEvent}: it confirms the payload is a
     * {@link WSO2ConsentRevokedEventPayload} carrying the receipt id, the subject read from the
     * receipt, and the service the purpose belonged to.
     *
     * @see #testAddedEventUsesEventTenant() for why the argument is asserted on a static mock.
     */
    @Test
    public void testRevokedEventUsesEventTenant() throws Exception {

        mockReceiptForRevocation();

        EventData eventData = mock(EventData.class);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_ID, RECEIPT_ID);
        when(eventData.getEventParams()).thenReturn(params);
        when(eventData.getTenantDomain()).thenReturn(SUB_ORG_TENANT_DOMAIN);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Answers.CALLS_REAL_METHODS)) {
            payloadUtils.when(() -> WSO2PayloadUtils.buildUser(anyString(), anyString(), anyString()))
                    .thenReturn(new User());

            List<EventPayload> payloads = builder.buildConsentRevokedEvent(eventData);

            assertEquals(payloads.size(), 1);
            assertTrue(payloads.get(0) instanceof WSO2ConsentRevokedEventPayload);
            payloadUtils.verify(() -> WSO2PayloadUtils.buildUser(USER_STORE_DOMAIN, SUBJECT_ID,
                    SUB_ORG_TENANT_DOMAIN));

            WSO2ConsentRevokedEventPayload payload = (WSO2ConsentRevokedEventPayload) payloads.get(0);
            assertEquals(payload.getTenant().getName(), TENANT_DOMAIN);
            assertEquals(payload.getConsent().getId(), RECEIPT_ID);
            assertEquals(payload.getConsent().getSubjectId(), SUBJECT_ID);
            assertEquals(payload.getConsent().getServiceId(), SERVICE_ID);
        }
    }

    /**
     * Verifies that a revoked consent falls back to the root tenant when the event carries no
     * tenant domain at all.
     * <p>
     * Covers the null arm of the guard, which is the state an {@link EventData} built without a
     * tenant domain arrives in; {@link #testAddedEventFallsBackToRootTenant()} covers the empty
     * arm on the added-consent path.
     *
     * @see #testAddedEventUsesEventTenant() for why the argument is asserted on a static mock.
     */
    @Test
    public void testRevokedEventFallsBackToRootTenant() throws Exception {

        mockReceiptForRevocation();

        EventData eventData = mock(EventData.class);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_ID, RECEIPT_ID);
        when(eventData.getEventParams()).thenReturn(params);
        when(eventData.getTenantDomain()).thenReturn(null);

        try (MockedStatic<WSO2PayloadUtils> payloadUtils =
                     mockStatic(WSO2PayloadUtils.class, Answers.CALLS_REAL_METHODS)) {
            payloadUtils.when(() -> WSO2PayloadUtils.buildUser(anyString(), anyString(), anyString()))
                    .thenReturn(new User());

            List<EventPayload> payloads = builder.buildConsentRevokedEvent(eventData);

            assertEquals(payloads.size(), 1);
            payloadUtils.verify(() -> WSO2PayloadUtils.buildUser(USER_STORE_DOMAIN, SUBJECT_ID,
                    TENANT_DOMAIN));
        }
    }


    /**
     * Event parameters carrying a V2 receipt with one service and one purpose. The single PII
     * category is unconsented, so it is skipped without the consent manager having to resolve a
     * category name -- these tests are about the tenant, not about the elements.
     */
    private Map<String, Object> buildReceiptInputParams() {

        ReceiptPurposeInput purposeInput = new ReceiptPurposeInput();
        purposeInput.setPurposeId(PURPOSE_ID_INT);
        purposeInput.setPurposeUuid(PURPOSE_UUID);
        purposeInput.setPurposeName(PURPOSE_NAME);
        purposeInput.setPurposeVersionId(PURPOSE_VERSION);
        purposeInput.setPiiCategory(
                Collections.singletonList(new PIICategoryValidity(1, "INDEFINITE", false)));

        ReceiptServiceInput serviceInput = new ReceiptServiceInput();
        serviceInput.setService(SERVICE_ID);
        serviceInput.setPurposes(Collections.singletonList(purposeInput));

        ReceiptInput receiptInput = new ReceiptInput();
        receiptInput.setConsentReceiptId(RECEIPT_ID);
        receiptInput.setPiiPrincipalId(SUBJECT_ID);
        receiptInput.setState("ACTIVE");
        receiptInput.setCollectionMethod("V2");
        receiptInput.setServices(Collections.singletonList(serviceInput));

        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.RECEIPT_INPUT, receiptInput);
        return params;
    }

    /**
     * Stubs the consent manager with a receipt the revocation path can walk. doReturn is used
     * rather than when/thenReturn because the consent manager is a class level mock that another
     * test in this class stubs to throw for the same receipt id.
     */
    private void mockReceiptForRevocation() throws ConsentManagementException {

        org.wso2.carbon.consent.mgt.core.model.ConsentPurpose consentPurpose =
                mock(org.wso2.carbon.consent.mgt.core.model.ConsentPurpose.class);
        when(consentPurpose.getUuid()).thenReturn(PURPOSE_UUID);
        when(consentPurpose.getPurpose()).thenReturn(PURPOSE_NAME);
        when(consentPurpose.getPurposeVersionId()).thenReturn(PURPOSE_VERSION);
        when(consentPurpose.getPiiCategory()).thenReturn(
                Collections.singletonList(new PIICategoryValidity(1, "INDEFINITE", false)));

        ReceiptService receiptService = mock(ReceiptService.class);
        when(receiptService.getService()).thenReturn(SERVICE_ID);
        when(receiptService.getPurposes()).thenReturn(Collections.singletonList(consentPurpose));

        Receipt receipt = mock(Receipt.class);
        when(receipt.getPiiPrincipalId()).thenReturn(SUBJECT_ID);
        when(receipt.getServices()).thenReturn(Collections.singletonList(receiptService));

        doReturn(receipt).when(consentManager).getReceiptWithExtendedSchema(RECEIPT_ID);
    }
}
