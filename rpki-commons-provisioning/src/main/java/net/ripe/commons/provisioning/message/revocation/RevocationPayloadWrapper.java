package net.ripe.commons.provisioning.message.revocation;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;

@XStreamAlias("message")
public class RevocationPayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamAlias("key")
    private RevocationPayload content;

    public RevocationPayloadWrapper(String sender, String recipient, RevocationPayload content) {
        super(sender, recipient, PayloadMessageType.revoke);

        this.content = content;
    }

    public RevocationPayload getPayloadContent() {
        return content;
    }
}
