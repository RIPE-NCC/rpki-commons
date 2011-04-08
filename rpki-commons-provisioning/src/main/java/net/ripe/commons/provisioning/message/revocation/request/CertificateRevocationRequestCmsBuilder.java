package net.ripe.commons.provisioning.message.revocation.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.revocation.AbstractCertificateRevocationCmsBuilder;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationRequestCmsBuilder extends AbstractCertificateRevocationCmsBuilder {
    
    private static final XStreamXmlSerializer<CertificateRevocationRequestPayloadWrapper> SERIALIZER = new CertificateRevocationRequestPayloadWrapperSerializerBuilder().build();

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        CertificateRevocationKeyElement payload = new CertificateRevocationKeyElement(className, publicKey);
        CertificateRevocationRequestPayloadWrapper wrapper = new CertificateRevocationRequestPayloadWrapper(sender, recipient, payload);
        return SERIALIZER.serialize(wrapper);
    }
}
