package net.ripe.rpki.commons.provisioning.payload.common;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import org.apache.commons.lang3.Validate;

import java.net.URI;
import java.util.List;

public class CertificateElementBuilder {

    private List<URI> certificatePublishedLocations;
    private IpResourceSet ipResourceSet;
    private X509ResourceCertificate certificate;

    public CertificateElementBuilder withCertificatePublishedLocations(List<URI> uris) {
        this.certificatePublishedLocations = uris;
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
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(certificatePublishedLocations);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");
        Validate.notNull(certificate, "No certificate provided");

        return new CertificateElement()
                .setIssuerCertificatePublicationLocation(certificatePublishedLocations)
                .setIpResourceSet(ipResourceSet)
                .setCertificate(certificate);
    }
}
