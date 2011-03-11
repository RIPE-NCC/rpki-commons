package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class ListResponsePayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ListResponsePayload> {

    public ListResponsePayloadSerializerBuilder() {
        super(ListResponsePayload.class);
    }

    @Override
    public XStreamXmlSerializer<ListResponsePayload> build() {
        getXStream().processAnnotations(ListResponsePayload.class);
        return super.build();
    }
}
