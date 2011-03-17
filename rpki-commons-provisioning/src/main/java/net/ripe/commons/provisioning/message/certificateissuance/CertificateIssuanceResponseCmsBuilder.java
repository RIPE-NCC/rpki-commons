package net.ripe.commons.provisioning.message.certificateissuance;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.common.ResourceClassCmsBuilder;

public class CertificateIssuanceResponseCmsBuilder extends ResourceClassCmsBuilder {

    private static final XStreamXmlSerializer<CertificateIssuanceResponsePayloadWrapper> SERIALIZER = new CertificateIssuanceResponsePayloadWrapperSerializerBuilder().build();

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        CertificateIssuanceResponsePayload payload = new CertificateIssuanceResponsePayload();

        super.setValuesInPayload(payload);

        CertificateIssuanceResponsePayloadWrapper wrapper = new CertificateIssuanceResponsePayloadWrapper(sender, recipient, payload);

        return SERIALIZER.serialize(wrapper);
    }
}
