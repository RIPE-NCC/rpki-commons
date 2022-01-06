package net.ripe.rpki.commons.provisioning.payload.common;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;

public abstract class AbstractPayloadBuilder<T extends AbstractProvisioningPayload> {

    public abstract T build();

}
