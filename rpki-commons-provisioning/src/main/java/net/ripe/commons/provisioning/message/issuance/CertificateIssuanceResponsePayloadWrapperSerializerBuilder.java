package net.ripe.commons.provisioning.message.issuance;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

class CertificateIssuanceResponsePayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateIssuanceResponsePayloadWrapper> {

    public CertificateIssuanceResponsePayloadWrapperSerializerBuilder() {
        super(CertificateIssuanceResponsePayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<CertificateIssuanceResponsePayloadWrapper> build() {
        getXStream().processAnnotations(CertificateIssuanceResponsePayload.class);
        return super.build();
    }
}
