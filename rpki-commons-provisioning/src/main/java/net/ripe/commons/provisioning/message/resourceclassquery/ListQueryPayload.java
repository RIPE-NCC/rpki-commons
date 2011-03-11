package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayload;
import net.ripe.commons.provisioning.message.ProvisioningPayloadClass;

@XStreamAlias("message")
public class ListQueryPayload extends ProvisioningPayload {
    protected ListQueryPayload(String sender, String recipient) {
        super(sender, recipient, PayloadMessageType.list);
    }

    @Override
    public ProvisioningPayloadClass getPayloadClass() {
        return null;
    }
}
