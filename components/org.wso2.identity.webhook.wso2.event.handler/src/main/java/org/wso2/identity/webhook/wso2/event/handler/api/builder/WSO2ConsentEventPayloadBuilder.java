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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.consent.mgt.core.ConsentManager;
import org.wso2.carbon.consent.mgt.core.exception.ConsentManagementException;
import org.wso2.carbon.consent.mgt.core.model.ConsentAuthorization;
import org.wso2.carbon.consent.mgt.core.model.PIICategory;
import org.wso2.carbon.consent.mgt.core.model.PIICategoryValidity;
import org.wso2.carbon.consent.mgt.core.model.Receipt;
import org.wso2.carbon.consent.mgt.core.model.ReceiptInput;
import org.wso2.carbon.consent.mgt.core.model.ReceiptPurposeInput;
import org.wso2.carbon.consent.mgt.core.model.ReceiptService;
import org.wso2.carbon.consent.mgt.core.model.ReceiptServiceInput;

import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_AUTHORIZE_CONSENT;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2ConsentAddedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2ConsentRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Consent;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.ConsentElement;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.ConsentPurpose;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.wso2.carbon.user.core.UserCoreConstants;

import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.AUTHZ_STATUS;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.RECEIPT_ID;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.RECEIPT_INPUT;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.REVOKE_STATE;

/**
 * WSO2 implementation of ConsentEventPayloadBuilder.
 */
public class WSO2ConsentEventPayloadBuilder implements ConsentEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2ConsentEventPayloadBuilder.class);
    private static final String DEFAULT_COLLECTION_METHOD = "V2";

    @Override
    public List<EventPayload> buildConsentAddedEvent(EventData eventData) throws IdentityEventException {

        if (POST_AUTHORIZE_CONSENT.equals(eventData.getEventName())) {
            return buildConsentAddedEventFromAuthorization(eventData);
        }
        return buildConsentAddedEventFromReceipt(eventData);
    }

    private List<EventPayload> buildConsentAddedEventFromReceipt(EventData eventData) throws IdentityEventException {

        Map<String, Object> params = eventData.getEventParams();
        ReceiptInput receiptInput = (ReceiptInput) params.get(RECEIPT_INPUT);

        // Skip events coming from V1 API.
        if (receiptInput == null || !DEFAULT_COLLECTION_METHOD.equals(receiptInput.getCollectionMethod())) {
            return Collections.emptyList();
        }

        String subjectId = receiptInput.getPiiPrincipalId();
        Tenant tenant = resolveTenant();
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();
        String[] userContext = resolveUserContext(subjectId);
        String userStoreDomain = userContext[0];
        String userName = userContext[1];
        String tenantDomain = tenant.getName();
        if (StringUtils.isNotEmpty(eventData.getTenantDomain())) {
            tenantDomain = eventData.getTenantDomain();
        }
        User user = WSO2PayloadUtils.buildUser(userStoreDomain, userName, tenantDomain);
        UserStore userStore = new UserStore(userStoreDomain);

        List<ReceiptServiceInput> services = receiptInput.getServices();
        if (services == null || services.isEmpty()) {
            return Collections.emptyList();
        }

        List<EventPayload> payloads = new ArrayList<>();
        for (ReceiptServiceInput service : services) {
            String serviceId = service.getService();
            if (service.getPurposes() == null) {
                continue;
            }
            for (ReceiptPurposeInput purposeInput : service.getPurposes()) {
                ConsentPurpose purpose = buildConsentPurposeFromInput(purposeInput);
                String state = StringUtils.isNotBlank(receiptInput.getState()) ? receiptInput.getState()
                        : ConsentAuthorization.AuthorizationStatus.APPROVED.name();
                Consent consent = new Consent.Builder()
                        .id(receiptInput.getConsentReceiptId())
                        .subjectId(subjectId)
                        .state(state)
                        .serviceId(serviceId)
                        .purpose(purpose)
                        .build();

                payloads.add(new WSO2ConsentAddedEventPayload.Builder()
                        .consent(consent)
                        .tenant(tenant)
                        .organization(organization)
                        .user(user)
                        .userStore(userStore)
                        .action(action)
                        .initiatorType(initiatorType)
                        .initiatorIpAddress(initiatorIpAddress)
                        .build());
            }
        }
        return payloads;
    }

    private List<EventPayload> buildConsentAddedEventFromAuthorization(EventData eventData) throws IdentityEventException {

        Map<String, Object> params = eventData.getEventParams();
        Object receiptIdParam = params.get(RECEIPT_ID);
        if (receiptIdParam == null) {
            return Collections.emptyList();
        }
        String receiptId = String.valueOf(receiptIdParam);
        String subjectId = (String) params.get(IdentityEventConstants.EventProperty.USER_NAME);
        String authzStatus = (String) params.get(AUTHZ_STATUS);

        Tenant tenant = resolveTenant();
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();
        String[] userContext = resolveUserContext(subjectId);
        String userStoreDomain = userContext[0];
        String userName = userContext[1];
        User user = WSO2PayloadUtils.buildUser(userStoreDomain, userName, tenant.getName());
        UserStore userStore = new UserStore(userStoreDomain);

        try {
            ConsentManager consentManager = WSO2EventHookHandlerDataHolder.getInstance().getConsentManager();
            Receipt receipt = consentManager.getReceiptWithExtendedSchema(receiptId);

            List<ReceiptService> services = receipt.getServices();
            if (services == null || services.isEmpty()) {
                return Collections.emptyList();
            }

            List<EventPayload> payloads = new ArrayList<>();
            for (ReceiptService service : services) {
                String serviceId = service.getService();
                if (service.getPurposes() == null) {
                    continue;
                }
                for (org.wso2.carbon.consent.mgt.core.model.ConsentPurpose purposeObj : service.getPurposes()) {
                    List<ConsentElement> elements = buildConsentElements(purposeObj.getPiiCategory());
                    ConsentPurpose purpose = new ConsentPurpose.Builder()
                            .id(purposeObj.getUuid())
                            .name(purposeObj.getPurpose())
                            .version(purposeObj.getPurposeVersionId())
                            .elements(elements.isEmpty() ? null : elements)
                            .build();
                    Consent consent = new Consent.Builder()
                            .id(receiptId)
                            .subjectId(subjectId)
                            .state(authzStatus)
                            .serviceId(serviceId)
                            .purpose(purpose)
                            .build();
                    payloads.add(new WSO2ConsentAddedEventPayload.Builder()
                            .consent(consent)
                            .tenant(tenant)
                            .organization(organization)
                            .user(user)
                            .userStore(userStore)
                            .action(action)
                            .initiatorType(initiatorType)
                            .initiatorIpAddress(initiatorIpAddress)
                            .build());
                }
            }
            return payloads;
        } catch (ConsentManagementException e) {
            throw new IdentityEventException("Error retrieving consent receipt for authorized event: " + receiptId, e);
        }
    }

    @Override
    public List<EventPayload> buildConsentRevokedEvent(EventData eventData) throws IdentityEventException {

        return buildConsentRevokedEventFromReceipt(eventData);
    }

    private List<EventPayload> buildConsentRevokedEventFromReceipt(EventData eventData) throws IdentityEventException {

        Map<String, Object> params = eventData.getEventParams();
        Object receiptIdParam = params.get(RECEIPT_ID);
        if (receiptIdParam == null) {
            return Collections.emptyList();
        }
        String receiptId = String.valueOf(receiptIdParam);

        Tenant tenant = resolveTenant();
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        try {
            ConsentManager consentManager = WSO2EventHookHandlerDataHolder.getInstance().getConsentManager();
            Receipt receipt = consentManager.getReceiptWithExtendedSchema(receiptId);

            String subjectId = receipt.getPiiPrincipalId();
            String[] userContext = resolveUserContext(subjectId);
            String userStoreDomain = userContext[0];
            String userName = userContext[1];
            String tenantDomain = tenant.getName();
            if (StringUtils.isNotEmpty(eventData.getTenantDomain())) {
                tenantDomain = eventData.getTenantDomain();
            }
            User user = WSO2PayloadUtils.buildUser(userStoreDomain, userName, tenantDomain);
            UserStore userStore = new UserStore(userStoreDomain);

            List<ReceiptService> services = receipt.getServices();
            if (services == null || services.isEmpty()) {
                return Collections.emptyList();
            }

            List<EventPayload> payloads = new ArrayList<>();
            for (ReceiptService service : services) {
                String serviceId = service.getService();
                if (service.getPurposes() == null) {
                    continue;
                }
                for (org.wso2.carbon.consent.mgt.core.model.ConsentPurpose purposeObj : service.getPurposes()) {
                    List<ConsentElement> elements = buildConsentElements(purposeObj.getPiiCategory());
                    ConsentPurpose purpose = new ConsentPurpose.Builder()
                            .id(purposeObj.getUuid())
                            .name(purposeObj.getPurpose())
                            .version(purposeObj.getPurposeVersionId())
                            .elements(elements.isEmpty() ? null : elements)
                            .build();
                    Consent consent = new Consent.Builder()
                            .id(receiptId)
                            .subjectId(subjectId)
                            .state(REVOKE_STATE)
                            .serviceId(serviceId)
                            .purpose(purpose)
                            .build();
                    payloads.add(new WSO2ConsentRevokedEventPayload.Builder()
                            .consent(consent)
                            .tenant(tenant)
                            .organization(organization)
                            .user(user)
                            .userStore(userStore)
                            .action(action)
                            .initiatorType(initiatorType)
                            .initiatorIpAddress(initiatorIpAddress)
                            .build());
                }
            }
            return payloads;
        } catch (ConsentManagementException e) {
            throw new IdentityEventException("Error retrieving consent receipt for revoked event: " + receiptId, e);
        }
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    private ConsentPurpose buildConsentPurposeFromInput(ReceiptPurposeInput purposeInput) {

        List<ConsentElement> elements = buildConsentElements(purposeInput.getPiiCategory());

        return new ConsentPurpose.Builder()
                .id(purposeInput.getPurposeUuid())
                .name(purposeInput.getPurposeName())
                .version(purposeInput.getPurposeVersionId())
                .elements(elements.isEmpty() ? null : elements)
                .build();
    }

    private List<ConsentElement> buildConsentElements(List<PIICategoryValidity> piiCategories) {

        List<ConsentElement> elements = new ArrayList<>();
        for (PIICategoryValidity category : piiCategories) {
            if (!category.isConsented()) {
                continue;
            }
            String name = StringUtils.isNotBlank(category.getName())
                    ? category.getName() : resolvePIICategoryName(category.getId());
            if (name != null) {
                elements.add(new ConsentElement(name));
            }
        }
        return elements;
    }

    private String resolvePIICategoryName(Integer id) {

        if (id == null) {
            return null;
        }
        try {
            ConsentManager consentManager = WSO2EventHookHandlerDataHolder.getInstance().getConsentManager();
            PIICategory piiCategory = consentManager.getPIICategory(id);
            return piiCategory != null ? piiCategory.getName() : null;
        } catch (ConsentManagementException e) {
            LOG.warn("Unable to resolve PII category name for id: " + id, e);
            return null;
        }
    }

    private String[] resolveUserContext(String subjectId) {

        if (subjectId != null && subjectId.contains("/")) {
            int idx = subjectId.indexOf('/');
            return new String[]{subjectId.substring(0, idx), subjectId.substring(idx + 1)};
        }
        return new String[]{UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME, subjectId};
    }

    private Tenant resolveTenant() {

        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());
        return new Tenant(rootTenantId, rootTenantDomain);
    }

}
