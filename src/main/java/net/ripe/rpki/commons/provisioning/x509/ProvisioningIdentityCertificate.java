package net.ripe.rpki.commons.provisioning.x509;

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

/**
 * A rfc8183 identity certificate.
 *
 * This is a self-signed X.509 BPKI certificate that will be the issuer of the BPKI EE certificates that the child uses
 * when sending provisioning protocol messages to the parent.
 */
public class ProvisioningIdentityCertificate extends ProvisioningCertificate implements Serializable {

    private static final long serialVersionUID = 1L;


    public ProvisioningIdentityCertificate(X509Certificate certificate) {
        super(certificate);

        // Check that certificate is self-signed
        try {
            this.verify(this.getPublicKey());
        } catch (InvalidKeyException | SignatureException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
