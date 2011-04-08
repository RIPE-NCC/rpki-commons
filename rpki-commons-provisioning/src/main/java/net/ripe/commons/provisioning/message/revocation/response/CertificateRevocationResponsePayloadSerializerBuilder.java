package net.ripe.commons.provisioning.message.revocation.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationResponsePayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateRevocationResponsePayload> {

    public CertificateRevocationResponsePayloadSerializerBuilder() {
        super(CertificateRevocationResponsePayload.class);
    }
    
    @Override
    public XStreamXmlSerializer<CertificateRevocationResponsePayload> build() {
        getXStream().processAnnotations(CertificateRevocationKeyElement.class);
        return super.build();
    }

}
