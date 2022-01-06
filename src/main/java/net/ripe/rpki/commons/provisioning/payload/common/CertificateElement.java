package net.ripe.rpki.commons.provisioning.payload.common;

import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.EqualsSupport;

import java.net.URI;
import java.util.Iterator;
import java.util.List;

public class CertificateElement extends EqualsSupport {

    private List<URI> issuerCertificatePublicationLocationUris;

    private IpResourceSet allocatedAsn;

    private IpResourceSet allocatedIpv4;

    private IpResourceSet allocatedIpv6;

    private X509ResourceCertificate certificate;

    // Setters
    public CertificateElement setIssuerCertificatePublicationLocation(List<URI> issuerCertificatePublicationLocation) {
        this.issuerCertificatePublicationLocationUris = issuerCertificatePublicationLocation;
        return this;
    }

    public CertificateElement setCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public CertificateElement setIpResourceSet(IpResourceSet ipResourceSet) {
        allocatedAsn = new IpResourceSet();
        allocatedIpv4 = new IpResourceSet();
        allocatedIpv6 = new IpResourceSet();

        Iterator<IpResource> iter = ipResourceSet.iterator();
        while (iter.hasNext()) {
            IpResource resource = iter.next();
            if (resource.getType().equals(IpResourceType.ASN)) {
                allocatedAsn.add(resource);
            } else if (resource.getType().equals(IpResourceType.IPv4)) {
                allocatedIpv4.add(resource);
            } else if (resource.getType().equals(IpResourceType.IPv6)) {
                allocatedIpv6.add(resource);
            }
        }

        return this;
    }

    // Getters
    public List<URI> getIssuerCertificatePublicationUris() {
        return issuerCertificatePublicationLocationUris;
    }

    public URI getRsyncAIAPointer() {
        for (URI uri : issuerCertificatePublicationLocationUris) {
            if ("rsync".equalsIgnoreCase(uri.getScheme())) {
                return uri;
            }
        }
        return null;

    }

    public IpResourceSet getAllocatedAsn() {
        return allocatedAsn;
    }

    public IpResourceSet getAllocatedIpv4() {
        return allocatedIpv4;
    }

    public IpResourceSet getAllocatedIpv6() {
        return allocatedIpv6;
    }

    public X509ResourceCertificate getCertificate() {
        return certificate;
    }

    public void setAllocatedAsn(IpResourceSet allocatedAsn) {
        this.allocatedAsn = allocatedAsn;
    }

    public void setAllocatedIpv4(IpResourceSet allocatedIpv4) {
        this.allocatedIpv4 = allocatedIpv4;
    }

    public void setAllocatedIpv6(IpResourceSet allocatedIpv6) {
        this.allocatedIpv6 = allocatedIpv6;
    }

}
