package net.ripe.commons.provisioning.payload.common;

import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;

public abstract class AbstractPayloadBuilder<T extends AbstractProvisioningPayload> {

    public abstract T build();
    
}
