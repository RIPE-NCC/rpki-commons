package net.ripe.commons.provisioning.message.list.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class ResourceClassListQueryPayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ResourceClassListQueryPayloadWrapper> {

    public ResourceClassListQueryPayloadSerializerBuilder() {
        super(ResourceClassListQueryPayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<ResourceClassListQueryPayloadWrapper> build() {
        getXStream().processAnnotations(ResourceClassListQueryPayloadWrapper.class);
        return super.build();
    }
}
