package net.ripe.commons.provisioning.payload.revocation.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.revocation.AbstractCertificateRevocationPayloadBuilder;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationResponsePayloadBuilder extends AbstractCertificateRevocationPayloadBuilder {

    private static final XStreamXmlSerializer<CertificateRevocationResponsePayload> SERIALIZER = new CertificateRevocationResponsePayloadSerializerBuilder().build();

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        CertificateRevocationKeyElement payload = new CertificateRevocationKeyElement(className, publicKey);
        CertificateRevocationResponsePayload wrapper = new CertificateRevocationResponsePayload(sender, recipient, payload);
        return SERIALIZER.serialize(wrapper);
    }

}
