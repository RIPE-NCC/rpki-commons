package net.ripe.rpki.commons.provisioning.payload.revocation.response;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningResponsePayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationResponsePayload extends AbstractProvisioningResponsePayload {

    private final CertificateRevocationKeyElement keyElement;

    public CertificateRevocationResponsePayload(CertificateRevocationKeyElement keyElement) {
        super(PayloadMessageType.revoke_response);
        this.keyElement = keyElement;
    }

    public CertificateRevocationKeyElement getKeyElement() {
        return keyElement;
    }

}
