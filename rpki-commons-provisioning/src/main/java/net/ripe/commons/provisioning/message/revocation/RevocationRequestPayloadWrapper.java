package net.ripe.commons.provisioning.message.revocation;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;

@XStreamAlias("message")
public class RevocationRequestPayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamAlias("key")
    private RevocationRequestPayload content;

    public RevocationRequestPayloadWrapper(String sender, String recipient, RevocationRequestPayload content) {
        super(sender, recipient, PayloadMessageType.revoke);

        this.content = content;
    }

    public RevocationRequestPayload getPayloadContent() {
        return content;
    }
}
