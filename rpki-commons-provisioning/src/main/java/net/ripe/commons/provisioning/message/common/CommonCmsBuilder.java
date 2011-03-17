package net.ripe.commons.provisioning.message.common;

import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import org.apache.commons.lang.Validate;

import java.security.PrivateKey;

public abstract class CommonCmsBuilder extends ProvisioningCmsObjectBuilder {
    private String sender;
    private String recipient;

    // TODO remove after parser decodes the content - strictly for junit testing
    public String xml;

    public void withSender(String sender) {
        this.sender = sender;
    }

    public void withRecipient(String recipient) {
        this.recipient = recipient;
    }

    public ProvisioningCmsObject build(PrivateKey privateKey) {
        validateFields();
        onValidateFields();

        String serializedPayloadWrapper = serializePayloadWrapper(sender, recipient);
        super.withPayloadContent(serializedPayloadWrapper);

        // TODO remove after parser decodes the content - strictly for junit testing
        xml = serializedPayloadWrapper;

        return super.build(privateKey);
    }

    protected void onValidateFields() {

    }

    protected abstract String serializePayloadWrapper(String sender, String recipient);

    private void validateFields() {
        Validate.notNull(sender, "Sender is required");
        Validate.notNull(recipient, "Recipient is required");
    }
}