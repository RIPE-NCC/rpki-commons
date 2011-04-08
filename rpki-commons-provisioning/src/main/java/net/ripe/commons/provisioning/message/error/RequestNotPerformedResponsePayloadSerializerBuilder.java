package net.ripe.commons.provisioning.message.error;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.ProvisioningPayloadXmlSerializerBuilder;

public class RequestNotPerformedResponsePayloadSerializerBuilder extends ProvisioningPayloadXmlSerializerBuilder<RequestNotPerformedResponsePayload> {

    public RequestNotPerformedResponsePayloadSerializerBuilder() {
        super(RequestNotPerformedResponsePayload.class);
    }

    @Override
    public XStreamXmlSerializer<RequestNotPerformedResponsePayload> build() {
        getXStream().processAnnotations(RequestNotPerformedResponsePayload.class);
        return super.build();
    }
}
