package net.ripe.commons.certification.validation.objectvalidators;

import net.ripe.commons.certification.CertificateRepositoryObjectFile;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;


public interface ResourceCertificateLocator {

	CertificateRepositoryObjectFile<X509ResourceCertificate> findParent(X509ResourceCertificate certificate);

	CertificateRepositoryObjectFile<X509Crl> findCrl(X509ResourceCertificate certificate);
}
