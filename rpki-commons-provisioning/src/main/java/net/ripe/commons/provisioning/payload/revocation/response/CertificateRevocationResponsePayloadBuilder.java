package net.ripe.commons.provisioning.payload.revocation.response;

import net.ripe.commons.provisioning.payload.revocation.AbstractCertificateRevocationPayloadBuilder;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

public class CertificateRevocationResponsePayloadBuilder extends AbstractCertificateRevocationPayloadBuilder<CertificateRevocationResponsePayload> {

    @Override
    public CertificateRevocationResponsePayload build() {
        CertificateRevocationKeyElement payload = new CertificateRevocationKeyElement(className, publicKey);
        return new CertificateRevocationResponsePayload(sender, recipient, payload);
    }

}
