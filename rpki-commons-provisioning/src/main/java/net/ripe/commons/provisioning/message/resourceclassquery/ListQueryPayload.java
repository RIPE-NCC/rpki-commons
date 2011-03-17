package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayload;

@XStreamAlias("message")
public class ListQueryPayload extends ProvisioningPayload {
    protected ListQueryPayload(String sender, String recipient) {
        super(sender, recipient, PayloadMessageType.list);
    }
}
