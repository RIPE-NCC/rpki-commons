package net.ripe.rpki.commons.provisioning.payload.revocation.request;

import net.ripe.rpki.commons.provisioning.payload.revocation.AbstractCertificateRevocationPayloadBuilder;
import net.ripe.rpki.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationRequestPayloadBuilder extends AbstractCertificateRevocationPayloadBuilder<CertificateRevocationRequestPayload> {

    @Override
    public CertificateRevocationRequestPayload build() {
        CertificateRevocationKeyElement payload = new CertificateRevocationKeyElement(getClassName(), getPublicKeyHash());
        return new CertificateRevocationRequestPayload(payload);
    }
}
