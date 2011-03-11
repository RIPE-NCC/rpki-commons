package net.ripe.commons.provisioning.message.resourceclassquery;


import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import org.apache.commons.lang.Validate;

import java.security.PrivateKey;

public class ListQueryCmsBuilder extends ProvisioningCmsObjectBuilder {
    private static final XStreamXmlSerializer<ListQueryPayload> SERIALIZER = new ListQueryPayloadSerializerBuilder().build();

    private String sender;
    private String recipient;

    // TODO remove after parser decodes the content - strictly for junit testing
    public String xml;

    public ListQueryCmsBuilder withSender(String sender) {
        this.sender = sender;
        return this;
    }

    public ListQueryCmsBuilder withRecipient(String recipient) {
        this.recipient = recipient;
        return this;
    }

    public ProvisioningCmsObject build(PrivateKey privateKey) {
        validateFields();

        String payload = createSerializedPayload();
        withPayloadContent(payload);

        return super.build(privateKey);
    }

    private String createSerializedPayload() {
        ListQueryPayload payload = new ListQueryPayload(sender, recipient);
        xml = SERIALIZER.serialize(payload);
        return xml;
    }

    private void validateFields() {
        Validate.notNull(sender, "Sender is required");
        Validate.notNull(recipient, "Recipient is required");
    }

}
