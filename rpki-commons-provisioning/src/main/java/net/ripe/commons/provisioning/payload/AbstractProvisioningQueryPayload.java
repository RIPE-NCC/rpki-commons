package net.ripe.commons.provisioning.payload;

/**
 * Marker class for Query type provisioning payloads
 */
public abstract class AbstractProvisioningQueryPayload extends AbstractProvisioningPayload {

    public AbstractProvisioningQueryPayload(PayloadMessageType type) {
        super(type);
    }

}
