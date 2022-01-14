package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObjectFile;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;


public interface ResourceCertificateLocator {

    CertificateRepositoryObjectFile<X509ResourceCertificate> findParent(X509ResourceCertificate certificate);

    CertificateRepositoryObjectFile<X509Crl> findCrl(X509ResourceCertificate certificate);
}
