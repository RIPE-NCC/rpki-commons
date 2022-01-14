package net.ripe.rpki.commons.provisioning.payload.issue.request;

import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * See <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1</a>
 */
public class CertificateIssuanceRequestElement extends EqualsSupport {

    private String className;
    private IpResourceSet allocatedAsn;
    private IpResourceSet allocatedIpv4;
    private IpResourceSet allocatedIpv6;
    private PKCS10CertificationRequest certificateRequest;

    public String getClassName() {
        return className;
    }

    CertificateIssuanceRequestElement setClassName(String className) {
        this.className = className;
        return this;
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

    CertificateIssuanceRequestElement setAllocatedAsn(IpResourceSet asns) {
        validateResourceSetContainsOnlyType(asns, IpResourceType.ASN);
        this.allocatedAsn = asns;
        return this;
    }

    CertificateIssuanceRequestElement setAllocatedIpv4(IpResourceSet allocatedIpv4) {
        validateResourceSetContainsOnlyType(allocatedIpv4, IpResourceType.IPv4);
        this.allocatedIpv4 = allocatedIpv4;
        return this;
    }

    CertificateIssuanceRequestElement setAllocatedIpv6(IpResourceSet allocatedIpv6) {
        validateResourceSetContainsOnlyType(allocatedIpv6, IpResourceType.IPv6);
        this.allocatedIpv6 = allocatedIpv6;
        return this;
    }

    private void validateResourceSetContainsOnlyType(IpResourceSet resourceSet, IpResourceType type) {
        if (resourceSet == null) {
            return;
        }
        for (IpResource resource : resourceSet) {
            Validate.isTrue(resource.getType().equals(type), "Can only add resources of type: " + type);
        }
    }


    public PKCS10CertificationRequest getCertificateRequest() {
        return certificateRequest;
    }

    CertificateIssuanceRequestElement setCertificateRequest(PKCS10CertificationRequest certificate) {
        this.certificateRequest = certificate;
        return this;
    }

}
