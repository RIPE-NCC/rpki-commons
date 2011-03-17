package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

class ListResponsePayloadWrapperSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ListResponsePayloadWrapper> {

    public ListResponsePayloadWrapperSerializerBuilder() {
        super(ListResponsePayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<ListResponsePayloadWrapper> build() {
        getXStream().processAnnotations(ListResponsePayload.class);
        return super.build();
    }
}
