package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayload;

@XStreamAlias("message")
public class ListResponsePayload extends ProvisioningPayload {

    @XStreamAlias("class")
    private ListResponsePayloadClass payloadClass;

    public ListResponsePayload(String sender, String recipient, PayloadMessageType type, ListResponsePayloadClass payloadClass) {
        super(sender, recipient, type);
        this.payloadClass = payloadClass;
    }

    @Override
    public ListResponsePayloadClass getPayloadClass() {
        return payloadClass;
    }
}
