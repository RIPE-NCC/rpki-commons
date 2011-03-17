package net.ripe.commons.provisioning.message.resourceclassquery;

import com.thoughtworks.xstream.annotations.XStreamConverter;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import org.apache.commons.lang.builder.ToStringBuilder;

@XStreamConverter(ResourceSetConverter.class)
public class ResourceSet {
    private String[] issuerCertificatePublicationLocation;

    private String[] allocatedAsn;

    private String[] allocatedIpv4;

    private String[] allocatedIpv6;

    private X509ResourceCertificate certificate;

    public String[] getIssuerCertificatePublicationLocation() {
        return issuerCertificatePublicationLocation;
    }

    ResourceSet setIssuerCertificatePublicationLocation(String[] issuerCertificatePublicationLocation) {
        this.issuerCertificatePublicationLocation = issuerCertificatePublicationLocation;
        return this;
    }

    public String[] getAllocatedAsn() {
        return allocatedAsn;
    }

    ResourceSet setAllocatedAsn(String[] allocatedAsn) {
        this.allocatedAsn = allocatedAsn;
        return this;
    }

    public String[] getAllocatedIpv4() {
        return allocatedIpv4;
    }

    ResourceSet setAllocatedIpv4(String[] allocatedIpv4) {
        this.allocatedIpv4 = allocatedIpv4;
        return this;
    }

    public String[] getAllocatedIpv6() {
        return allocatedIpv6;
    }

    ResourceSet setAllocatedIpv6(String[] allocatedIpv6) {
        this.allocatedIpv6 = allocatedIpv6;
        return this;
    }

    public X509ResourceCertificate getCertificate() {
        return certificate;
    }

    ResourceSet setCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
