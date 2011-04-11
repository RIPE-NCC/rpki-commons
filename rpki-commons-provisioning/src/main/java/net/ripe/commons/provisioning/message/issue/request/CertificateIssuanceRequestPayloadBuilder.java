package net.ripe.commons.provisioning.message.issue.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.message.common.AbstractPayloadBuilder;
import net.ripe.ipresource.IpResourceSet;
import org.apache.commons.lang.Validate;
import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * Builder for 'Certificate Issuance Request'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1</a>
 */
public class CertificateIssuanceRequestPayloadBuilder extends AbstractPayloadBuilder {
    private static final XStreamXmlSerializer<CertificateIssuanceRequestPayload> SERIALIZER = new CertificateIssuanceRequestPayloadSerializerBuilder().build();

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
     * Provide empty list to request *all* eligible Asns. Leave null to request none.
     */
    public CertificateIssuanceRequestPayloadBuilder withAllocatedAsn(IpResourceSet asnResourceSet) {
        this.asn = asnResourceSet;
        return this;
    }

    /**
     * Provide empty list to request *all* eligible IPv4. Leave null to request none.
     */
    public CertificateIssuanceRequestPayloadBuilder withIpv4ResourceSet(IpResourceSet ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
        return this;
    }

    /**
     * Provide empty list to request *all* eligible IPv6. Leave null to request none.
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
    protected String serializePayloadWrapper(String sender, String recipient) {
        CertificateIssuanceRequestElement content = new CertificateIssuanceRequestElement()
                .setClassName(className)
                .setAllocatedAsn(asn)
                .setAllocatedIpv4(ipv4ResourceSet)
                .setAllocatedIpv6(ipv6ResourceSet)
                .setCertificate(certificateRequest);

        CertificateIssuanceRequestPayload payload = new CertificateIssuanceRequestPayload(sender, recipient, content);

        return SERIALIZER.serialize(payload);
    }

    @Override
    protected void onValidateFields() {
        Validate.notNull(className, "No className provided");
        Validate.notNull(certificateRequest);
    }
}
