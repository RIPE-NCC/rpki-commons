package net.ripe.rpki.commons.provisioning.payload.revocation.request;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningQueryPayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationRequestPayload extends AbstractProvisioningQueryPayload {

    private final CertificateRevocationKeyElement keyElement;

    public CertificateRevocationRequestPayload(CertificateRevocationKeyElement keyElement) {
        super(PayloadMessageType.revoke);
        this.keyElement = keyElement;
    }

    public CertificateRevocationKeyElement getKeyElement() {
        return keyElement;
    }
}
