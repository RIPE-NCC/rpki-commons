package net.ripe.rpki.commons.provisioning.payload.list.request;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningQueryPayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;

public class ResourceClassListQueryPayload extends AbstractProvisioningQueryPayload {

    protected ResourceClassListQueryPayload() {
        super(PayloadMessageType.list);
    }

}
