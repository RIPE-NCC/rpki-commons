package net.ripe.commons.provisioning.payload;

import static net.ripe.commons.certification.validation.ValidationString.VALID_PAYLOAD_TYPE;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.NotImplementedException;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.provisioning.payload.error.RequestNotPerformedResponsePayload;
import net.ripe.commons.provisioning.payload.error.RequestNotPerformedResponsePayloadSerializerBuilder;
import net.ripe.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload;
import net.ripe.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadSerializerBuilder;
import net.ripe.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayload;
import net.ripe.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayloadSerializerBuilder;
import net.ripe.commons.provisioning.payload.list.request.ResourceClassListQueryPayload;
import net.ripe.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadSerializerBuilder;
import net.ripe.commons.provisioning.payload.list.response.ResourceClassListResponsePayload;
import net.ripe.commons.provisioning.payload.list.response.ResourceClassListResponsePayloadSerializerBuilder;
import net.ripe.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayload;
import net.ripe.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayloadSerializerBuilder;
import net.ripe.commons.provisioning.payload.revocation.response.CertificateRevocationResponsePayload;
import net.ripe.commons.provisioning.payload.revocation.response.CertificateRevocationResponsePayloadSerializerBuilder;


public final class PayloadParser {







    private static final Pattern TYPE_PATTERN = Pattern.compile(".*<message[^>]*type=['\"]([a-z|\\_]*)['\"].*", Pattern.DOTALL);

    private static final XStreamXmlSerializer<ResourceClassListResponsePayload> LIST_RESPONSE_SERIALIZER = new ResourceClassListResponsePayloadSerializerBuilder().build();
    private static final XStreamXmlSerializer<ResourceClassListQueryPayload> LIST_SERIALIZER = new ResourceClassListQueryPayloadSerializerBuilder().build();
    private static final XStreamXmlSerializer<CertificateIssuanceRequestPayload> ISSUE_SERIALIZER = new CertificateIssuanceRequestPayloadSerializerBuilder().build();
    private static final XStreamXmlSerializer<CertificateIssuanceResponsePayload> ISSUE_RESPONSE_SERIALIZER = new CertificateIssuanceResponsePayloadSerializerBuilder().build();
    private static final XStreamXmlSerializer<CertificateRevocationRequestPayload> REVOKE_SERIALIZER = new CertificateRevocationRequestPayloadSerializerBuilder().build();
    private static final XStreamXmlSerializer<CertificateRevocationResponsePayload> REVOKE_RESPONSE_SERIALIZER = new CertificateRevocationResponsePayloadSerializerBuilder().build();
    private static final XStreamXmlSerializer<RequestNotPerformedResponsePayload> ERROR_RESPONSE_SERIALIZER = new RequestNotPerformedResponsePayloadSerializerBuilder().build();

    private static final Map<PayloadMessageType, XStreamXmlSerializer<? extends AbstractProvisioningPayload>> TYPE_MAP = new HashMap<PayloadMessageType, XStreamXmlSerializer<? extends AbstractProvisioningPayload>>();
    static {
        TYPE_MAP.put(PayloadMessageType.list, LIST_SERIALIZER);
        TYPE_MAP.put(PayloadMessageType.list_response, LIST_RESPONSE_SERIALIZER);
        TYPE_MAP.put(PayloadMessageType.issue, ISSUE_SERIALIZER);
        TYPE_MAP.put(PayloadMessageType.issue_response, ISSUE_RESPONSE_SERIALIZER);
        TYPE_MAP.put(PayloadMessageType.revoke, REVOKE_SERIALIZER);
        TYPE_MAP.put(PayloadMessageType.revoke_response, REVOKE_RESPONSE_SERIALIZER);
        TYPE_MAP.put(PayloadMessageType.error_response, ERROR_RESPONSE_SERIALIZER);
    }

    private PayloadParser() {
    }

    public static AbstractProvisioningPayload parse(byte[] encoded, ValidationResult validationResult) {
        String payloadXml = new String(encoded);

        Matcher matcher = TYPE_PATTERN.matcher(payloadXml);

        boolean matches = matcher.matches();

        validationResult.isTrue(matches, ValidationString.FOUND_PAYLOAD_TYPE);

        if (matches) {
            String type = matcher.group(1);

            boolean isValidType = PayloadMessageType.containsAsEnum(type);

            validationResult.isTrue(isValidType, VALID_PAYLOAD_TYPE);

            if (isValidType) {
                PayloadMessageType messageType = PayloadMessageType.valueOf(type);

                XStreamXmlSerializer<? extends AbstractProvisioningPayload> serializer = TYPE_MAP.get(messageType);
                return serializer.deserialize(payloadXml);
            }
        }

        return null;
    }

    public static String serialize(AbstractProvisioningPayload payload) {
        PayloadMessageType type = payload.getType();
        switch (type) {
        case list:
            return LIST_SERIALIZER.serialize((ResourceClassListQueryPayload) payload);
        case list_response:
            return LIST_RESPONSE_SERIALIZER.serialize((ResourceClassListResponsePayload) payload);
        case issue:
            return ISSUE_SERIALIZER.serialize((CertificateIssuanceRequestPayload) payload);
        case issue_response:
            return ISSUE_RESPONSE_SERIALIZER.serialize((CertificateIssuanceResponsePayload) payload);
        case revoke:
            return REVOKE_SERIALIZER.serialize((CertificateRevocationRequestPayload) payload);
        case revoke_response:
            return REVOKE_RESPONSE_SERIALIZER.serialize((CertificateRevocationResponsePayload) payload);
        case error_response:
            return ERROR_RESPONSE_SERIALIZER.serialize((RequestNotPerformedResponsePayload) payload);
        default:
            throw new NotImplementedException("Don't have serializer for PayloadMessageType: " + type);
        }
    }
}
