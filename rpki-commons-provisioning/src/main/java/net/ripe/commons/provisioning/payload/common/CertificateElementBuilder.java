package net.ripe.commons.provisioning.payload.common;

import java.net.URI;
import java.util.List;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;

public class CertificateElementBuilder {
    
    private List<URI> issuerCertificatePublicationLocation;
    private IpResourceSet ipResourceSet;
    private X509ResourceCertificate certificate;

    public CertificateElementBuilder withIssuerCertificatePublicationLocation(List<URI> uris) {
        this.issuerCertificatePublicationLocation = uris;
        return this;
    }

    public CertificateElementBuilder withIpResources(IpResourceSet ipResourceSet) {
        this.ipResourceSet = ipResourceSet;
        return this;
    }

    public CertificateElementBuilder withCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public CertificateElement build() {
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(issuerCertificatePublicationLocation);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(certificate);

        return new CertificateElement()
                .setIssuerCertificatePublicationLocation(issuerCertificatePublicationLocation)
                .setIpResourceSet(ipResourceSet)
                .setCertificate(certificate);
    }
}
