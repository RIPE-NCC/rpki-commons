package net.ripe.commons.provisioning.message.revocation;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class RevocationRequestPayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<RevocationRequestPayloadWrapper> {

    public RevocationRequestPayloadWrapperSerializerBuilder() {
        super(RevocationRequestPayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<RevocationRequestPayloadWrapper> build() {
        getXStream().processAnnotations(RevocationRequestPayload.class);
        return super.build();
    }
}
