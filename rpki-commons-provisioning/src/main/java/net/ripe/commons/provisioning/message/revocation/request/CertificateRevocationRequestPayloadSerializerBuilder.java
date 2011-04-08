package net.ripe.commons.provisioning.message.revocation.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationRequestPayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateRevocationRequestPayload> {

    public CertificateRevocationRequestPayloadSerializerBuilder() {
        super(CertificateRevocationRequestPayload.class);
    }

    @Override
    public XStreamXmlSerializer<CertificateRevocationRequestPayload> build() {
        getXStream().processAnnotations(CertificateRevocationKeyElement.class);
        return super.build();
    }
}
