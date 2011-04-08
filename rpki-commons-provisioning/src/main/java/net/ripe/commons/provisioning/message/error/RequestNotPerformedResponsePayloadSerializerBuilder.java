package net.ripe.commons.provisioning.message.error;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class RequestNotPerformedResponsePayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<RequestNotPerformedResponsePayloadWrapper> {

    public RequestNotPerformedResponsePayloadSerializerBuilder() {
        super(RequestNotPerformedResponsePayloadWrapper.class);
    }

    @Override
    public XStreamXmlSerializer<RequestNotPerformedResponsePayloadWrapper> build() {
        getXStream().processAnnotations(RequestNotPerformedResponsePayloadWrapper.class);
        return super.build();
    }
}
