package net.ripe.commons.provisioning.message.error;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class NotPerformedPayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<NotPerformedPayloadWrapper> {

    public NotPerformedPayloadSerializerBuilder() {
        super(NotPerformedPayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<NotPerformedPayloadWrapper> build() {
        getXStream().processAnnotations(NotPerformedPayloadWrapper.class);
        return super.build();
    }
}
