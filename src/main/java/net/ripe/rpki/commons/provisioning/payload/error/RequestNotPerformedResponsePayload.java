package net.ripe.rpki.commons.provisioning.payload.error;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningResponsePayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;

public class RequestNotPerformedResponsePayload extends AbstractProvisioningResponsePayload {

    private NotPerformedError status;

    private String description;

    protected RequestNotPerformedResponsePayload(NotPerformedError status, String description) {
        super(PayloadMessageType.error_response);
        this.status = status;
        this.description = description;
    }

    public NotPerformedError getStatus() {
        return status;
    }

    public String getDescription() {
        return description;
    }
}
