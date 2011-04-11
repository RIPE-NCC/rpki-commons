package net.ripe.commons.provisioning.payload.list.request;

import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class ResourceClassListQueryPayload extends AbstractProvisioningPayload {

    protected ResourceClassListQueryPayload(String sender, String recipient) {
        super(sender, recipient, PayloadMessageType.list);
    }
}
