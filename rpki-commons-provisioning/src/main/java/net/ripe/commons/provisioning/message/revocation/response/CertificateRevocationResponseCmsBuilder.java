package net.ripe.commons.provisioning.message.revocation.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.revocation.AbstractCertificateRevocationCmsBuilder;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationResponseCmsBuilder extends AbstractCertificateRevocationCmsBuilder {

    private static final XStreamXmlSerializer<CertificateRevocationResponsePayloadWrapper> SERIALIZER = new CertificateRevocationResponsePayloadWrapperSerializerBuilder().build();

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        CertificateRevocationKeyElement payload = new CertificateRevocationKeyElement(className, publicKey);
        CertificateRevocationResponsePayloadWrapper wrapper = new CertificateRevocationResponsePayloadWrapper(sender, recipient, payload);
        return SERIALIZER.serialize(wrapper);
    }

}
