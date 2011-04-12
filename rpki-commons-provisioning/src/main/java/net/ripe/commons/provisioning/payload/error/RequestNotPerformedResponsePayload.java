package net.ripe.commons.provisioning.payload.error;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamConverter;

import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;

@XStreamAlias("message")
public class RequestNotPerformedResponsePayload extends AbstractProvisioningPayload {

    @XStreamConverter(NotPerformedErrorConverter.class)
    private NotPerformedError status;

    @XStreamConverter(DescriptionElementConverter.class)
    private String description;

    protected RequestNotPerformedResponsePayload(String sender, String recipient, NotPerformedError status, String description) {
        super(sender, recipient, PayloadMessageType.error_response);
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
