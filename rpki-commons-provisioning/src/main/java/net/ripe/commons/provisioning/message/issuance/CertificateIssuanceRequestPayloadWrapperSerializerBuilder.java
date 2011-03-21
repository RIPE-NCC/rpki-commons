package net.ripe.commons.provisioning.message.issuance;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class CertificateIssuanceRequestPayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateIssuanceRequestPayloadWrapper> {

    public CertificateIssuanceRequestPayloadWrapperSerializerBuilder() {
        super(CertificateIssuanceRequestPayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<CertificateIssuanceRequestPayloadWrapper> build() {
        getXStream().processAnnotations(CertificateIssuanceRequestPayloadWrapper.class);
        return super.build();
    }
}
