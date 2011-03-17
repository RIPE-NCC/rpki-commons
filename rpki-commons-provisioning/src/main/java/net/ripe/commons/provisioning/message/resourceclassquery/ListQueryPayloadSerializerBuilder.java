package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

class ListQueryPayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ListQueryPayloadWrapper> {

    ListQueryPayloadSerializerBuilder() {
        super(ListQueryPayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<ListQueryPayloadWrapper> build() {
        getXStream().processAnnotations(ListQueryPayloadWrapper.class);
        return super.build();
    }
}
