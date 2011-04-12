package net.ripe.commons.provisioning.payload.error;

import net.ripe.commons.provisioning.payload.AbstractProvisioningResponsePayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamConverter;

@XStreamAlias("message")
public class RequestNotPerformedResponsePayload extends AbstractProvisioningResponsePayload {

    @XStreamConverter(NotPerformedErrorConverter.class)
    private NotPerformedError status;

    @XStreamConverter(DescriptionElementConverter.class)
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
