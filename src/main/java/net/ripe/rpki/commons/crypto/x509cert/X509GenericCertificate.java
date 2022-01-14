package net.ripe.rpki.commons.crypto.x509cert;

import java.security.cert.X509Certificate;

public abstract class X509GenericCertificate extends AbstractX509CertificateWrapper implements X509CertificateObject {
    protected X509GenericCertificate(X509Certificate certificate) {
        super(certificate);
    }
}
