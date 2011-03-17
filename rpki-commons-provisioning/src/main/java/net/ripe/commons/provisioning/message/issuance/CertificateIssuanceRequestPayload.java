package net.ripe.commons.provisioning.message.issuance;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.bouncycastle.jce.PKCS10CertificationRequest;

public class CertificateIssuanceRequestPayload {
    private String className;
    private String[] allocatedAsn;
    private String[] allocatedIpv4;
    private String[] allocatedIpv6;
    private PKCS10CertificationRequest certificate;

    public String getClassName() {
        return className;
    }

    CertificateIssuanceRequestPayload setClassName(String className) {
        this.className = className;
        return this;
    }

    public String[] getAllocatedAsn() {
        return allocatedAsn;
    }

    CertificateIssuanceRequestPayload setAllocatedAsn(String[] allocatedAsn) {
        this.allocatedAsn = allocatedAsn;
        return this;
    }

    public String[] getAllocatedIpv4() {
        return allocatedIpv4;
    }

    CertificateIssuanceRequestPayload setAllocatedIpv4(String[] allocatedIpv4) {
        this.allocatedIpv4 = allocatedIpv4;
        return this;
    }

    public String[] getAllocatedIpv6() {
        return allocatedIpv6;
    }

    CertificateIssuanceRequestPayload setAllocatedIpv6(String[] allocatedIpv6) {
        this.allocatedIpv6 = allocatedIpv6;
        return this;
    }

    public PKCS10CertificationRequest getCertificate() {
        return certificate;
    }

    CertificateIssuanceRequestPayload setCertificate(PKCS10CertificationRequest certificate) {
        this.certificate = certificate;
        return this;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}
