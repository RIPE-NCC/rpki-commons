package net.ripe.commons.provisioning.payload.common;

import org.apache.commons.lang.Validate;

public abstract class AbstractPayloadBuilder {
    private String sender;
    private String recipient;

    public void withSender(String sender) {
        this.sender = sender;
    }

    public void withRecipient(String recipient) {
        this.recipient = recipient;
    }

    protected void onValidateFields() {

    }

    protected abstract String serializePayloadWrapper(String sender, String recipient);


    public String build() {
        onValidateFields();

        Validate.notNull(sender, "Sender is required");
        Validate.notNull(recipient, "Recipient is required");

        return serializePayloadWrapper(sender, recipient);
    }

}
