package net.ripe.commons.provisioning.message.common;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class ResourceClassPayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ResourceClassPayloadWrapper> {

    public ResourceClassPayloadWrapperSerializerBuilder() {
        super(ResourceClassPayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<ResourceClassPayloadWrapper> build() {
        getXStream().processAnnotations(ResourceClassPayload.class);
        return super.build();
    }
}
