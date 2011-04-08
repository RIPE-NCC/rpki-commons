package net.ripe.commons.provisioning.message.revocation.response;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.ProvisioningPayloadWrapper;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class CertificateRevocationResponsePayloadWrapper extends ProvisioningPayloadWrapper {

    @XStreamAlias("key")
    private CertificateRevocationKeyElement keyElement;

    public CertificateRevocationResponsePayloadWrapper(String sender, String recipient, CertificateRevocationKeyElement keyElement) {
        super(sender, recipient, PayloadMessageType.revoke_response);
        this.keyElement = keyElement;
    }

    public CertificateRevocationKeyElement getKeyElement() {
        return keyElement;
    }

}
