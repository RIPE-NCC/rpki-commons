package net.ripe.commons.provisioning.message;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.certification.client.xml.XStreamXmlSerializerBuilder;

public class ProvisioningPayloadXmlSerializerBuilder extends XStreamXmlSerializerBuilder<ProvisioningPayload> {

    public ProvisioningPayloadXmlSerializerBuilder() {
        super(ProvisioningPayload.class);

        withAttribute("sender", ProvisioningPayload.class);
        withAttribute("recipient", ProvisioningPayload.class);
        withAttribute("version", ProvisioningPayload.class);

        withAliasType("message", ProvisioningPayload.class);

        withAttribute("type", ProvisioningPayload.class);
    }

    public XStreamXmlSerializer<ProvisioningPayload> build() {
        return new ProvisioningPayloadXmlSerializer(getXStream(), ProvisioningPayload.class);
    }
}
