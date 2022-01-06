package net.ripe.rpki.commons.provisioning.payload.common;

import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.EqualsSupport;
import org.joda.time.DateTime;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;


public class GenericClassElement extends EqualsSupport {

    private String className;

    private List<URI> certificateAuthorityUri;

    private IpResourceSet resourceSetAs = new IpResourceSet();

    private IpResourceSet resourceSetIpv4 = new IpResourceSet();

    private IpResourceSet resourceSetIpv6 = new IpResourceSet();

    private List<CertificateElement> certificateElements = new ArrayList<CertificateElement>();

    private X509ResourceCertificate issuer;

    private DateTime validityNotAfter;

    private String siaHeadUri;

    public DateTime getValidityNotAfter() {
        return validityNotAfter;
    }

    public void setValidityNotAfter(DateTime validityNotAfter) {
        this.validityNotAfter = validityNotAfter;
    }

    public String getSiaHeadUri() {
        return siaHeadUri;
    }

    public void setSiaHeadUri(String siaHeadUri) {
        this.siaHeadUri = siaHeadUri;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public List<URI> getCertificateAuthorityUri() {
        return certificateAuthorityUri;
    }

    public void setCertUris(List<URI> certUris) {
        this.certificateAuthorityUri = certUris;
    }

    public IpResourceSet getResourceSetAsn() {
        return resourceSetAs;
    }

    public IpResourceSet getResourceSetIpv4() {
        return resourceSetIpv4;
    }

    public IpResourceSet getResourceSetIpv6() {
        return resourceSetIpv6;
    }

    public void setResourceSetAs(IpResourceSet resourceSetAs) {
        this.resourceSetAs = resourceSetAs;
    }

    public void setResourceSetIpv4(IpResourceSet resourceSetIpv4) {
        this.resourceSetIpv4 = resourceSetIpv4;
    }

    public void setResourceSetIpv6(IpResourceSet resourceSetIpv6) {
        this.resourceSetIpv6 = resourceSetIpv6;
    }

    public void setIpResourceSet(IpResourceSet ipResourceSet) {
        IpResourceSet asns = new IpResourceSet();
        IpResourceSet ipv4 = new IpResourceSet();
        IpResourceSet ipv6 = new IpResourceSet();

        for (IpResource resource : ipResourceSet) {
            switch (resource.getType()) {
                case ASN:
                    asns.add(resource);
                    break;
                case IPv4:
                    ipv4.add(resource);
                    break;
                case IPv6:
                    ipv6.add(resource);
                    break;
            }
        }

        resourceSetAs = asns;
        resourceSetIpv4 = ipv4;
        resourceSetIpv6 = ipv6;
    }


    public X509ResourceCertificate getIssuer() {
        return issuer;
    }

    public void setIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
    }

    public List<CertificateElement> getCertificateElements() {
        return certificateElements;
    }

    public void setCertificateElements(List<CertificateElement> certificateElements) {
        this.certificateElements = certificateElements;
    }

}

