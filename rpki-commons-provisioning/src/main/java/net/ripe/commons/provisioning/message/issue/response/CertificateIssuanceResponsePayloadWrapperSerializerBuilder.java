package net.ripe.commons.provisioning.message.issue.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class CertificateIssuanceResponsePayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateIssuanceResponsePayloadWrapper> {

    public CertificateIssuanceResponsePayloadWrapperSerializerBuilder() {
        super(CertificateIssuanceResponsePayloadWrapper.class);
    }
    
    @Override
    public XStreamXmlSerializer<CertificateIssuanceResponsePayloadWrapper> build() {
        getXStream().processAnnotations(CertificateIssuanceResponsePayloadWrapper.class);
        return super.build();
    }

}
