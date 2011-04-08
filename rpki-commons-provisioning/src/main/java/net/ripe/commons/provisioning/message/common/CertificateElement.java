package net.ripe.commons.provisioning.message.common;

import com.thoughtworks.xstream.annotations.XStreamConverter;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import org.apache.commons.lang.builder.ToStringBuilder;

@XStreamConverter(CertificateElementConverter.class)
public class CertificateElement {
    
    private String[] issuerCertificatePublicationLocation;

    private String[] allocatedAsn;

    private String[] allocatedIpv4;

    private String[] allocatedIpv6;

    private X509ResourceCertificate certificate;

    public String[] getIssuerCertificatePublicationLocation() {
        return issuerCertificatePublicationLocation;
    }

    CertificateElement setIssuerCertificatePublicationLocation(String[] issuerCertificatePublicationLocation) {   // NOPMD no clone of array stored
        this.issuerCertificatePublicationLocation = issuerCertificatePublicationLocation;
        return this;
    }

    public String[] getAllocatedAsn() {
        return allocatedAsn;
    }

    CertificateElement setAllocatedAsn(String[] allocatedAsn) {       // NOPMD no clone of array stored
        this.allocatedAsn = allocatedAsn;
        return this;
    }

    public String[] getAllocatedIpv4() {
        return allocatedIpv4;
    }

    CertificateElement setAllocatedIpv4(String[] allocatedIpv4) {   // NOPMD no clone of array stored
        this.allocatedIpv4 = allocatedIpv4;
        return this;
    }

    public String[] getAllocatedIpv6() {
        return allocatedIpv6;
    }

    CertificateElement setAllocatedIpv6(String[] allocatedIpv6) {   // NOPMD no clone of array stored
        this.allocatedIpv6 = allocatedIpv6;
        return this;
    }

    public X509ResourceCertificate getCertificate() {
        return certificate;
    }

    CertificateElement setCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }
}
