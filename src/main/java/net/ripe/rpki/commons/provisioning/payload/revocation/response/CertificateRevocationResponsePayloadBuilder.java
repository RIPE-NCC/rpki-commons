package net.ripe.rpki.commons.provisioning.payload.revocation.response;

import net.ripe.rpki.commons.provisioning.payload.revocation.AbstractCertificateRevocationPayloadBuilder;
import net.ripe.rpki.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationResponsePayloadBuilder extends AbstractCertificateRevocationPayloadBuilder<CertificateRevocationResponsePayload> {

    @Override
    public CertificateRevocationResponsePayload build() {
        CertificateRevocationKeyElement payload = new CertificateRevocationKeyElement(getClassName(), getPublicKeyHash());
        return new CertificateRevocationResponsePayload(payload);
    }

}
