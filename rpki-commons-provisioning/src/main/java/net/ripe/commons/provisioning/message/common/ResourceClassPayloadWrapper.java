package net.ripe.commons.provisioning.message.common;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;
import org.apache.commons.lang.builder.ToStringBuilder;

public class ResourceClassPayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamAlias("class")
    private ResourceClassPayload payloadClass;

    public ResourceClassPayloadWrapper(String sender, String recipient, ResourceClassPayload payloadClass, PayloadMessageType messageType) {
        super(sender, recipient, messageType);
        this.payloadClass = payloadClass;
    }

    public ResourceClassPayload getPayloadClass() {
        return payloadClass;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}
