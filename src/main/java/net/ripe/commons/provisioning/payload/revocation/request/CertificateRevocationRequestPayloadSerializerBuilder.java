package net.ripe.commons.provisioning.payload.revocation.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.ProvisioningPayloadXmlSerializerBuilder;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

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
