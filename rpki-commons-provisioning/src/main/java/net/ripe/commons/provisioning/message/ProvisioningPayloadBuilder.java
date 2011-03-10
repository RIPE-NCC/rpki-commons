package net.ripe.commons.provisioning.message;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import org.apache.commons.lang.Validate;

import java.io.IOException;

public abstract class ProvisioningPayloadBuilder extends ProvisioningCmsObjectBuilder {
    private static final Integer SUPPORT_VERSION = 1;
    private String sender;
    private String recipient;
    private PayloadMessageType messageType;

    // TODO remove, now for junit testing
    private String xml;

    // TODO remove, now for junit testing
    public String getXml() {
        return xml;
    }

    protected ProvisioningPayloadBuilder(PayloadMessageType messageType) {
        this.messageType = messageType;
    }

    public ProvisioningPayloadBuilder withSender(String sender) {
        this.sender = sender;
        return this;
    }

    public ProvisioningPayloadBuilder withRecipient(String recipient) {
        this.recipient = recipient;
        return this;
    }

    protected String serializePayload() throws IOException {
        Validate.notNull(sender, "Sender is required");
        Validate.notNull(recipient, "Recipient is required");
        Validate.notNull(messageType, "Message type is required");

        ProvisioningPayload payload = new ProvisioningPayload(SUPPORT_VERSION, sender, recipient, messageType);

        XStreamXmlSerializer<ProvisioningPayload> serializer = new ProvisioningPayloadXmlSerializerBuilder().build();

        // TODO remove
        xml = serializer.serialize(payload);
        return xml;
    }
}
