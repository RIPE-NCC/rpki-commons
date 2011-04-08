package net.ripe.commons.provisioning.message.list.request;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class ResourceClassListQueryPayloadWrapper extends ProvisioningPayloadWrapper {

    protected ResourceClassListQueryPayloadWrapper(String sender, String recipient) {
        super(sender, recipient, PayloadMessageType.list);
    }
}
