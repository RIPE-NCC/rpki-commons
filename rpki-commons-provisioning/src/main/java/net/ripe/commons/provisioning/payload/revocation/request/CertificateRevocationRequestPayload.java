package net.ripe.commons.provisioning.payload.revocation.request;

import net.ripe.commons.provisioning.payload.AbstractProvisioningQueryPayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class CertificateRevocationRequestPayload extends AbstractProvisioningQueryPayload {

    @XStreamAlias("key")
    private CertificateRevocationKeyElement keyElement;

    public CertificateRevocationRequestPayload(CertificateRevocationKeyElement keyElement) {
        super(PayloadMessageType.revoke);
        this.keyElement = keyElement;
    }

    public CertificateRevocationKeyElement getKeyElement() {
        return keyElement;
    }
}
