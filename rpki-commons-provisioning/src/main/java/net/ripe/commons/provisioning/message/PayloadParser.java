package net.ripe.commons.provisioning.message;

import static net.ripe.commons.certification.validation.ValidationString.VALID_PAYLOAD_TYPE;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.provisioning.message.error.RequestNotPerformedResponsePayloadSerializerBuilder;
import net.ripe.commons.provisioning.message.issue.request.CertificateIssuanceRequestPayloadWrapperSerializerBuilder;
import net.ripe.commons.provisioning.message.issue.response.CertificateIssuanceResponsePayloadWrapperSerializerBuilder;
import net.ripe.commons.provisioning.message.list.request.ResourceClassListQueryPayloadSerializerBuilder;
import net.ripe.commons.provisioning.message.list.response.ResourceClassListResponsePayloadWrapperSerializerBuilder;
import net.ripe.commons.provisioning.message.revocation.request.CertificateRevocationRequestPayloadWrapperSerializerBuilder;
import net.ripe.commons.provisioning.message.revocation.response.CertificateRevocationResponsePayloadWrapperSerializerBuilder;

public final class PayloadParser {
    private static final Pattern TYPE_PATTERN = Pattern.compile(".*<message[^>]*type=['\"]([a-z|\\_]*)['\"].*", Pattern.DOTALL);

    private static final Map<PayloadMessageType, XStreamXmlSerializer<? extends ProvisioningPayloadWrapper>> TYPE_MAP = new HashMap<PayloadMessageType, XStreamXmlSerializer<? extends ProvisioningPayloadWrapper>>();

    static {
        TYPE_MAP.put(PayloadMessageType.list_response, new ResourceClassListResponsePayloadWrapperSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.list, new ResourceClassListQueryPayloadSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.issue, new CertificateIssuanceRequestPayloadWrapperSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.issue_response, new CertificateIssuanceResponsePayloadWrapperSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.revoke, new CertificateRevocationRequestPayloadWrapperSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.revoke_response, new CertificateRevocationResponsePayloadWrapperSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.error_response, new RequestNotPerformedResponsePayloadSerializerBuilder().build());
    }

    private PayloadParser() {
    }

    public static ProvisioningPayloadWrapper parse(byte[] encoded, ValidationResult validationResult) {
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

                XStreamXmlSerializer<? extends ProvisioningPayloadWrapper> serializer = TYPE_MAP.get(messageType);
                return serializer.deserialize(payloadXml);
            }
        }

        return null;
    }
}
