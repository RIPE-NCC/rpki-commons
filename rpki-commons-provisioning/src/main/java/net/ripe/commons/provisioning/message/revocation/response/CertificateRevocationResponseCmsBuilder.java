package net.ripe.commons.provisioning.message.revocation.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.revocation.AbstractCertificateRevocationCmsBuilder;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationResponseCmsBuilder extends AbstractCertificateRevocationCmsBuilder {

    private static final XStreamXmlSerializer<CertificateRevocationResponsePayload> SERIALIZER = new CertificateRevocationResponsePayloadSerializerBuilder().build();

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        CertificateRevocationKeyElement payload = new CertificateRevocationKeyElement(className, publicKey);
        CertificateRevocationResponsePayload wrapper = new CertificateRevocationResponsePayload(sender, recipient, payload);
        return SERIALIZER.serialize(wrapper);
    }

}
