package net.ripe.commons.provisioning.payload.list.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.ProvisioningPayloadXmlSerializerBuilder;

public class ResourceClassListQueryPayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ResourceClassListQueryPayload> {

    public ResourceClassListQueryPayloadSerializerBuilder() {
        super(ResourceClassListQueryPayload.class);
    }

    @Override
    public XStreamXmlSerializer<ResourceClassListQueryPayload> build() {
        getXStream().processAnnotations(ResourceClassListQueryPayload.class);
        return super.build();
    }
}
