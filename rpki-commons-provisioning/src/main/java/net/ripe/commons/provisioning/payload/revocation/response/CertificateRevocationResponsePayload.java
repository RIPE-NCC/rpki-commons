package net.ripe.commons.provisioning.payload.revocation.response;

import net.ripe.commons.provisioning.payload.AbstractProvisioningResponsePayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

import com.thoughtworks.xstream.annotations.XStreamAlias;

@XStreamAlias("message")
public class CertificateRevocationResponsePayload extends AbstractProvisioningResponsePayload {

    @XStreamAlias("key")
    private CertificateRevocationKeyElement keyElement;

    public CertificateRevocationResponsePayload(CertificateRevocationKeyElement keyElement) {
        super(PayloadMessageType.revoke_response);
        this.keyElement = keyElement;
    }

    public CertificateRevocationKeyElement getKeyElement() {
        return keyElement;
    }

}
