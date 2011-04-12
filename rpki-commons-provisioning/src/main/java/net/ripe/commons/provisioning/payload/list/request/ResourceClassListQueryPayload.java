package net.ripe.commons.provisioning.payload.list.request;

import net.ripe.commons.provisioning.payload.AbstractProvisioningQueryPayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class ResourceClassListQueryPayload extends AbstractProvisioningQueryPayload {

    protected ResourceClassListQueryPayload() {
        super(PayloadMessageType.list);
    }
}
