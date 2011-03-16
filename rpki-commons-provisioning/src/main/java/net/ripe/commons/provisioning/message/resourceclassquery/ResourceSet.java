package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamConverter;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;


@XStreamConverter(ResourceSetConverter.class)

public class ResourceSet {
    private String[] issuerCertificatePublicationLocation;

    private String[] resourceSetAsNumbers;

    private String[] resourceSetIpv4;

    private String[] resourceSetIpv6;

    private X509ResourceCertificate certificate;

    public String[] getIssuerCertificatePublicationLocation() {
        return issuerCertificatePublicationLocation;
    }

    ResourceSet setIssuerCertificatePublicationLocation(String[] issuerCertificatePublicationLocation) {
        this.issuerCertificatePublicationLocation = issuerCertificatePublicationLocation;
        return this;
    }

    public String[] getResourceSetAsNumbers() {
        return resourceSetAsNumbers;
    }

    ResourceSet setResourceSetAsNumbers(String[] resourceSetAsNumbers) {
        this.resourceSetAsNumbers = resourceSetAsNumbers;
        return this;
    }

    public String[] getResourceSetIpv4() {
        return resourceSetIpv4;
    }

    ResourceSet setResourceSetIpv4(String[] resourceSetIpv4) {
        this.resourceSetIpv4 = resourceSetIpv4;
        return this;
    }

    public String[] getResourceSetIpv6() {
        return resourceSetIpv6;
    }

    ResourceSet setResourceSetIpv6(String[] resourceSetIpv6) {
        this.resourceSetIpv6 = resourceSetIpv6;
        return this;
    }

    public X509ResourceCertificate getCertificate() {
        return certificate;
    }

    ResourceSet setCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }
}
