package net.ripe.commons.provisioning.message.list.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class ResourceClassListResponsePayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ResourceClassListResponsePayloadWrapper> {

    public ResourceClassListResponsePayloadWrapperSerializerBuilder() {
        super(ResourceClassListResponsePayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<ResourceClassListResponsePayloadWrapper> build() {
        getXStream().processAnnotations(ResourceClassListResponseClassElement.class);
        return super.build();
    }
}
