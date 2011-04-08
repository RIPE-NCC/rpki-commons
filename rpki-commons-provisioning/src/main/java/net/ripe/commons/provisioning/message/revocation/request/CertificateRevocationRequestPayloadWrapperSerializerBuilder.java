package net.ripe.commons.provisioning.message.revocation.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationRequestPayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateRevocationRequestPayloadWrapper> {

    public CertificateRevocationRequestPayloadWrapperSerializerBuilder() {
        super(CertificateRevocationRequestPayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<CertificateRevocationRequestPayloadWrapper> build() {
        getXStream().processAnnotations(CertificateRevocationKeyElement.class);
        return super.build();
    }
}
