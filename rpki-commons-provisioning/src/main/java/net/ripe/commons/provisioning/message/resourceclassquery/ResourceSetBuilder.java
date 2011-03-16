package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import org.apache.commons.lang.Validate;

public class ResourceSetBuilder {
    private String[] certificateAuthorityUri;
    private String[] asn;
    private String[] ipv4ResourceSet;
    private String[] ipv6ResourceSet;
    private X509ResourceCertificate certificate;

    public ResourceSetBuilder withAllocatedAsn(String... asn) {
        this.asn = asn;
        return this;
    }

    public ResourceSetBuilder withCertificateAuthorityUri(String... caUri) {
        this.certificateAuthorityUri = caUri;
        return this;
    }

    public ResourceSetBuilder withIpv4ResourceSet(String... ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
        return this;
    }

    public ResourceSetBuilder withIpv6ResourceSet(String... ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
        return this;
    }

    public ResourceSetBuilder withCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public ResourceSet build() {
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(certificateAuthorityUri);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(certificate);

        ResourceSet resourceSet = new ResourceSet()
                .setIssuerCertificatePublicationLocation(certificateAuthorityUri)
                .setResourceSetIpv4(ipv4ResourceSet != null ? ipv4ResourceSet : null)
                .setResourceSetIpv6(ipv6ResourceSet != null ? ipv6ResourceSet : null)
                .setResourceSetAsNumbers(asn)
                .setCertificate(certificate);

        return resourceSet;
    }

}
