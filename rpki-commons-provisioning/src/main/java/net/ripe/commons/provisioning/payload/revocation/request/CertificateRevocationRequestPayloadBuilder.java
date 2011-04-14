package net.ripe.commons.provisioning.payload.revocation.request;

import net.ripe.commons.provisioning.payload.revocation.AbstractCertificateRevocationPayloadBuilder;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationRequestPayloadBuilder extends AbstractCertificateRevocationPayloadBuilder<CertificateRevocationRequestPayload> {

    @Override
    public CertificateRevocationRequestPayload build() {
        CertificateRevocationKeyElement payload = new CertificateRevocationKeyElement(getClassName(), getPublicKey());
        return new CertificateRevocationRequestPayload(payload);
    }
}
