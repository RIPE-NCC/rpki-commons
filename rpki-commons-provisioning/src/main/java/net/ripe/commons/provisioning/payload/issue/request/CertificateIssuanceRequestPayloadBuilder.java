package net.ripe.commons.provisioning.payload.issue.request;

import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;
import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * Builder for 'Certificate Issuance Request'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1</a>
 */
public class CertificateIssuanceRequestPayloadBuilder extends AbstractPayloadBuilder<CertificateIssuanceRequestPayload> {

    private String className;
    private IpResourceSet asn;
    private IpResourceSet ipv4ResourceSet;
    private IpResourceSet ipv6ResourceSet;
    private PKCS10CertificationRequest certificateRequest;

    public CertificateIssuanceRequestPayloadBuilder withClassName(String className) {
        this.className = className;
        return this;
    }

    /**
     * Provide empty list to request *NO* Asns. Leave null to request *ALL* eligible.
     */
    public CertificateIssuanceRequestPayloadBuilder withAllocatedAsn(IpResourceSet asnResourceSet) {
        this.asn = asnResourceSet;
        return this;
    }

    /**
     * Provide empty list to request *NO* IPv4. Leave null to request *ALL* eligible.
     */
    public CertificateIssuanceRequestPayloadBuilder withIpv4ResourceSet(IpResourceSet ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
        return this;
    }

    /**
     * Provide empty list to request *NO* IPv6. Leave null to request *ALL* eligible.
     */
    public CertificateIssuanceRequestPayloadBuilder withIpv6ResourceSet(IpResourceSet ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
        return this;
    }


    public CertificateIssuanceRequestPayloadBuilder withCertificateRequest(PKCS10CertificationRequest certificateRequest) {
        this.certificateRequest = certificateRequest;
        return this;
    }

    @Override
    public CertificateIssuanceRequestPayload build() {
        Validate.notNull(className, "No className provided");
        Validate.notNull(certificateRequest);
        CertificateIssuanceRequestElement content = new CertificateIssuanceRequestElement()
                .setClassName(className)
                .setAllocatedAsn(asn)
                .setAllocatedIpv4(ipv4ResourceSet)
                .setAllocatedIpv6(ipv6ResourceSet)
                .setCertificateRequest(certificateRequest);

        return new CertificateIssuanceRequestPayload(content);
    }
}
