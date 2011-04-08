package net.ripe.commons.provisioning.message.list.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class ResourceClassListResponsePayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ResourceClassListResponsePayload> {

    public ResourceClassListResponsePayloadSerializerBuilder() {
        super(ResourceClassListResponsePayload.class);
    }

    @Override
    public XStreamXmlSerializer<ResourceClassListResponsePayload> build() {
        getXStream().processAnnotations(ResourceClassListResponseClassElement.class);
        return super.build();
    }
}
