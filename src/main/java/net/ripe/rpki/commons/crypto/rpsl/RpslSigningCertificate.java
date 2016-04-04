package net.ripe.rpki.commons.crypto.rpsl;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;

import java.security.cert.X509Certificate;

/**
 * Defines an EE certificate used for RPSL signing.
 * See: https://tools.ietf.org/html/draft-ietf-sidr-rpsl-sig-10
 */
public class RpslSigningCertificate extends X509ResourceCertificate {

    protected RpslSigningCertificate(X509ResourceCertificate certificate) {
        super(certificate.getCertificate());
    }


}
