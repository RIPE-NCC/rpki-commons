package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;

@XStreamAlias("message")
public class ListResponsePayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamAlias("class")
    private ListResponsePayload payload;

    public ListResponsePayloadWrapper(String sender, String recipient, ListResponsePayload payload) {
        super(sender, recipient, PayloadMessageType.list_response);
        this.payload = payload;
    }

    public ListResponsePayload getPayloadClass() {
        return payload;
    }
}
