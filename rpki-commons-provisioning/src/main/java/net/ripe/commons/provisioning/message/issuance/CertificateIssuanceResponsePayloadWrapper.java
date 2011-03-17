package net.ripe.commons.provisioning.message.issuance;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;

@XStreamAlias("message")
public class CertificateIssuanceResponsePayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamAlias("class")
    private CertificateIssuanceResponsePayload payload;

    public CertificateIssuanceResponsePayloadWrapper(String sender, String recipient, CertificateIssuanceResponsePayload payload) {
        super(sender, recipient, PayloadMessageType.issue_response);
        this.payload = payload;
    }

    public CertificateIssuanceResponsePayload getPayloadClass() {
        return payload;
    }

}
