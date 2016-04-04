package net.ripe.rpki.commons.crypto.rpsl;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;

/**
 * Simple wrapper to parse a RpslSigningCertificate
 *
 * For the moment not being fussy about validating that the certificate is set up as expected,
 * e.g. that it's an EE certificate, has the right key usage, no SIA, but yes AKI etc.
 *
 * For the proof of concept work this may not matter, and if it does we can just add it.
 */
public class RpslSigningCertificateParser {

    private RpslSigningCertificate resourceCertificate;

    public void parse(ValidationResult validationResult, byte[] encoded) {

        X509ResourceCertificateParser certificateParser = new X509ResourceCertificateParser();
        certificateParser.parse(validationResult, encoded);

        resourceCertificate = new RpslSigningCertificate(certificateParser.getCertificate());
    }

    public RpslSigningCertificate getRpslSigningCertificate() {
        return resourceCertificate;
    }
}
