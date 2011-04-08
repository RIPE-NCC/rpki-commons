package net.ripe.commons.provisioning.message.common;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.apache.commons.lang.Validate;

public class CertificateElementBuilder {
    
    private String[] issuerCertificatePublicationLocation;
    private String[] allocatedAsn;
    private String[] allocatedIpv4;
    private String[] allocatedIpv6;
    private X509ResourceCertificate certificate;

    public CertificateElementBuilder withIssuerCertificatePublicationLocation(String... caUri) {
        this.issuerCertificatePublicationLocation = caUri;
        return this;
    }

    public CertificateElementBuilder withAllocatedAsn(String... asn) {
        this.allocatedAsn = asn;
        return this;
    }

    public CertificateElementBuilder withAllocatedIpv4(String... ipv4ResourceSet) {
        this.allocatedIpv4 = ipv4ResourceSet;
        return this;
    }

    public CertificateElementBuilder withAllocatedIpv6(String... ipv6ResourceSet) {
        this.allocatedIpv6 = ipv6ResourceSet;
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
        Validate.isTrue(ResourceClassUtil.validateAsn(allocatedAsn), "AS numbers should not start with AS");

        return new CertificateElement()
                .setIssuerCertificatePublicationLocation(issuerCertificatePublicationLocation)
                .setAllocatedIpv4(allocatedIpv4 != null ? allocatedIpv4 : null)
                .setAllocatedIpv6(allocatedIpv6 != null ? allocatedIpv6 : null)
                .setAllocatedAsn(allocatedAsn)
                .setCertificate(certificate);
    }
}
