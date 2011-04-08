package net.ripe.commons.provisioning.message.list.request;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.AbstractProvisioningPayload;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class ResourceClassListQueryPayload extends AbstractProvisioningPayload {

    protected ResourceClassListQueryPayload(String sender, String recipient) {
        super(sender, recipient, PayloadMessageType.list);
    }
}
