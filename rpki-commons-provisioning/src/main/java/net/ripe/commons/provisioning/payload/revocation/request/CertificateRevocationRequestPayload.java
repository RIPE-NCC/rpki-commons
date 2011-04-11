package net.ripe.commons.provisioning.payload.revocation.request;

import com.thoughtworks.xstream.annotations.XStreamAlias;

import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

@XStreamAlias("message")
public class CertificateRevocationRequestPayload extends AbstractProvisioningPayload {

    @XStreamAlias("key")
    private CertificateRevocationKeyElement keyElement;

    public CertificateRevocationRequestPayload(String sender, String recipient, CertificateRevocationKeyElement keyElement) {
        super(sender, recipient, PayloadMessageType.revoke);
        this.keyElement = keyElement;
    }

    public CertificateRevocationKeyElement getKeyElement() {
        return keyElement;
    }
}
