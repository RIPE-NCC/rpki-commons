package net.ripe.commons.provisioning.message.revocation.response;

import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class CertificateRevocationResponsePayload extends AbstractProvisioningPayload {

    @XStreamAlias("key")
    private CertificateRevocationKeyElement keyElement;

    public CertificateRevocationResponsePayload(String sender, String recipient, CertificateRevocationKeyElement keyElement) {
        super(sender, recipient, PayloadMessageType.revoke_response);
        this.keyElement = keyElement;
    }

    public CertificateRevocationKeyElement getKeyElement() {
        return keyElement;
    }

}
