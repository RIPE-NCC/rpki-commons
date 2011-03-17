package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import org.apache.commons.lang.Validate;

public class ResourceSetBuilder {
    private String[] issuerCertificatePublicationLocation;
    private String[] allocatedAsn;
    private String[] allocatedIpv4;
    private String[] allocatedIpv6;
    private X509ResourceCertificate certificate;

    public ResourceSetBuilder withAllocatedAsn(String... asn) {
        this.allocatedAsn = asn;
        return this;
    }

    public ResourceSetBuilder withIssuerCertificatePublicationLocation(String... caUri) {
        this.issuerCertificatePublicationLocation = caUri;
        return this;
    }

    public ResourceSetBuilder withAllocatedIpv4(String... ipv4ResourceSet) {
        this.allocatedIpv4 = ipv4ResourceSet;
        return this;
    }

    public ResourceSetBuilder withAllocatedIpv6(String... ipv6ResourceSet) {
        this.allocatedIpv6 = ipv6ResourceSet;
        return this;
    }

    public ResourceSetBuilder withCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public ResourceSet build() {
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(issuerCertificatePublicationLocation);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(certificate);
        Validate.isTrue(ResourceClassUtil.validateAsn(allocatedAsn), "AS numbers should not start with AS");

        ResourceSet resourceSet = new ResourceSet()
                .setIssuerCertificatePublicationLocation(issuerCertificatePublicationLocation)
                .setAllocatedIpv4(allocatedIpv4 != null ? allocatedIpv4 : null)
                .setAllocatedIpv6(allocatedIpv6 != null ? allocatedIpv6 : null)
                .setAllocatedAsn(allocatedAsn)
                .setCertificate(certificate);

        return resourceSet;
    }

}
