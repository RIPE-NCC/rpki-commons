package net.ripe.commons.provisioning.payload.common;

import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;

import org.apache.commons.lang.Validate;

public abstract class AbstractPayloadBuilder<T extends AbstractProvisioningPayload> {
    
    protected String sender;
    protected String recipient;

    public void withSender(String sender) {
        this.sender = sender;
    }

    public void withRecipient(String recipient) {
        this.recipient = recipient;
    }

    /**
     * Override and call super to validate fields
     */
    protected void onValidateFields() {
        Validate.notNull(sender, "Sender is required");
        Validate.notNull(recipient, "Recipient is required");
    }

    public abstract T build();
}
