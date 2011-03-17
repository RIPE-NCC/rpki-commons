package net.ripe.commons.provisioning.message.certificateissuance;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

class CertificateIssuanceRequestPayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateIssuanceRequestPayload> {

    public CertificateIssuanceRequestPayloadSerializerBuilder() {
        super(CertificateIssuanceRequestPayload.class);
    }

    @Override
    public XStreamXmlSerializer<CertificateIssuanceRequestPayload> build() {
        getXStream().processAnnotations(CertificateIssuanceRequestPayload.class);
        return super.build();
    }
}
