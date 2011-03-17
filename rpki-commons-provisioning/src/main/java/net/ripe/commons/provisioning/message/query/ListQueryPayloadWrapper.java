package net.ripe.commons.provisioning.message.query;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;

@XStreamAlias("message")
public class ListQueryPayloadWrapper extends ProvisioningPayloadWrapper {
    protected ListQueryPayloadWrapper(String sender, String recipient) {
        super(sender, recipient, PayloadMessageType.list);
    }
}
