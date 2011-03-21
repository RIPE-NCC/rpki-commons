package net.ripe.commons.provisioning.message;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.common.ResourceClassPayloadWrapper;
import net.ripe.commons.provisioning.message.common.ResourceClassPayloadWrapperSerializerBuilder;
import net.ripe.commons.provisioning.message.error.NotPerformedPayloadSerializerBuilder;
import net.ripe.commons.provisioning.message.issuance.CertificateIssuanceRequestPayloadWrapperSerializerBuilder;
import net.ripe.commons.provisioning.message.query.ListQueryPayloadSerializerBuilder;
import net.ripe.commons.provisioning.message.revocation.RevocationPayloadWrapperSerializerBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PayloadParser {
    private static final Pattern TYPE_PATTERN = Pattern.compile(".*<message[^>]*type=['\"]([a-z|\\_]*)['\"].*", Pattern.DOTALL);

    private static final Map<PayloadMessageType, XStreamXmlSerializer<? extends ProvisioningPayloadWrapper>> TYPE_MAP = new HashMap<PayloadMessageType, XStreamXmlSerializer<? extends ProvisioningPayloadWrapper>>();

    static {
        XStreamXmlSerializer<ResourceClassPayloadWrapper> resourceClassSerializer = new ResourceClassPayloadWrapperSerializerBuilder().build();

        TYPE_MAP.put(PayloadMessageType.list_response, resourceClassSerializer);
        TYPE_MAP.put(PayloadMessageType.list, new ListQueryPayloadSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.issue, new CertificateIssuanceRequestPayloadWrapperSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.issue_response, resourceClassSerializer);
        TYPE_MAP.put(PayloadMessageType.revoke, new RevocationPayloadWrapperSerializerBuilder().build());
        TYPE_MAP.put(PayloadMessageType.error_response, new NotPerformedPayloadSerializerBuilder().build());
    }

    private PayloadParser() {
    }

    public static ProvisioningPayloadWrapper parse(byte[] encoded) {
//        byte[] decoded = Base64.decodeBase64(base64Encoded);

        String payloadXml = new String(encoded);

        Matcher matcher = TYPE_PATTERN.matcher(payloadXml);
        
        if (matcher.matches()) {
            String type = matcher.group(1);

            PayloadMessageType messageType = PayloadMessageType.valueOf(type);

            XStreamXmlSerializer<? extends ProvisioningPayloadWrapper> serializer = TYPE_MAP.get(messageType);
            return serializer.deserialize(payloadXml);
        }

        throw new IllegalArgumentException("Can't parse message type");
    }
}
