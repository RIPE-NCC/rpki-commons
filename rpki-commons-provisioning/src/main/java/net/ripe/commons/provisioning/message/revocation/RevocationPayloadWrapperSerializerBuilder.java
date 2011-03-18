package net.ripe.commons.provisioning.message.revocation;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class RevocationPayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<RevocationPayloadWrapper> {

    public RevocationPayloadWrapperSerializerBuilder() {
        super(RevocationPayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<RevocationPayloadWrapper> build() {
        getXStream().processAnnotations(RevocationPayload.class);
        return super.build();
    }
}
