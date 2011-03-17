package net.ripe.commons.provisioning.message.common;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import org.apache.commons.lang.Validate;

public class ResourceClassBuilder {
    private String[] issuerCertificatePublicationLocation;
    private String[] allocatedAsn;
    private String[] allocatedIpv4;
    private String[] allocatedIpv6;
    private X509ResourceCertificate certificate;

    public ResourceClassBuilder withAllocatedAsn(String... asn) {
        this.allocatedAsn = asn;
        return this;
    }

    public ResourceClassBuilder withIssuerCertificatePublicationLocation(String... caUri) {
        this.issuerCertificatePublicationLocation = caUri;
        return this;
    }

    public ResourceClassBuilder withAllocatedIpv4(String... ipv4ResourceSet) {
        this.allocatedIpv4 = ipv4ResourceSet;
        return this;
    }

    public ResourceClassBuilder withAllocatedIpv6(String... ipv6ResourceSet) {
        this.allocatedIpv6 = ipv6ResourceSet;
        return this;
    }

    public ResourceClassBuilder withCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public ResourceClass build() {
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(issuerCertificatePublicationLocation);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(certificate);
        Validate.isTrue(ResourceClassUtil.validateAsn(allocatedAsn), "AS numbers should not start with AS");

        ResourceClass resourceClass = new ResourceClass()
                .setIssuerCertificatePublicationLocation(issuerCertificatePublicationLocation)
                .setAllocatedIpv4(allocatedIpv4 != null ? allocatedIpv4 : null)
                .setAllocatedIpv6(allocatedIpv6 != null ? allocatedIpv6 : null)
                .setAllocatedAsn(allocatedAsn)
                .setCertificate(certificate);

        return resourceClass;
    }
}
