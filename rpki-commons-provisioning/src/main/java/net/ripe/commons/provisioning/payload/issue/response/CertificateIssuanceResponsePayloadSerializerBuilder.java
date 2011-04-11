package net.ripe.commons.provisioning.payload.issue.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.ProvisioningPayloadXmlSerializerBuilder;

public class CertificateIssuanceResponsePayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<CertificateIssuanceResponsePayload> {

    public CertificateIssuanceResponsePayloadSerializerBuilder() {
        super(CertificateIssuanceResponsePayload.class);
    }
    
    @Override
    public XStreamXmlSerializer<CertificateIssuanceResponsePayload> build() {
        getXStream().processAnnotations(CertificateIssuanceResponsePayload.class);
        return super.build();
    }

}
