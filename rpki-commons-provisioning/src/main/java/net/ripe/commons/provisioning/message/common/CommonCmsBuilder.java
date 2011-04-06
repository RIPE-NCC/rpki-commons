package net.ripe.commons.provisioning.message.common;

import java.security.PrivateKey;

import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;

import org.apache.commons.lang.Validate;

public abstract class CommonCmsBuilder extends ProvisioningCmsObjectBuilder {

    private String recipient;


    public void withRecipient(String recipient) {
        this.recipient = recipient;
    }

    @Override
    public ProvisioningCmsObject build(PrivateKey privateKey) {
        validateFields();
        onValidateFields();

        String serializedPayloadWrapper = serializePayloadWrapper(getCaDnName(), recipient);
        super.withPayloadContent(serializedPayloadWrapper);

        return super.build(privateKey);
    }

    protected void onValidateFields() {
    }

    protected abstract String serializePayloadWrapper(String sender, String recipient);

    private void validateFields() {
        Validate.notNull(recipient, "Recipient is required");
    }
}