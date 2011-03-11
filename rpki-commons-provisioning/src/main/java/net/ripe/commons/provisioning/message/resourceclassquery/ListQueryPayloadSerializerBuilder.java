package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class ListQueryPayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<ListQueryPayload> {

    public ListQueryPayloadSerializerBuilder() {
        super(ListQueryPayload.class);
    }

    @Override
    public XStreamXmlSerializer<ListQueryPayload> build() {
        getXStream().processAnnotations(ListQueryPayload.class);
        return super.build();
    }
}
