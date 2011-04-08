package net.ripe.commons.provisioning.message.revocation.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationResponsePayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateRevocationResponsePayloadWrapper> {

    public CertificateRevocationResponsePayloadWrapperSerializerBuilder() {
        super(CertificateRevocationResponsePayloadWrapper.class);
    }
    
    @Override
    public XStreamXmlSerializer<CertificateRevocationResponsePayloadWrapper> build() {
        getXStream().processAnnotations(CertificateRevocationKeyElement.class);
        return super.build();
    }

}
