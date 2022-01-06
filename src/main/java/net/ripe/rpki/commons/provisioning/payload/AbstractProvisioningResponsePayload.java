package net.ripe.rpki.commons.provisioning.payload;

/**
 * Marker class for 'Response' type provisioning payloads
 */
public abstract class AbstractProvisioningResponsePayload extends AbstractProvisioningPayload {

    public AbstractProvisioningResponsePayload(PayloadMessageType type) {
        super(type);
    }

}
