package net.ripe.commons.provisioning.message.issue.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import net.ripe.commons.provisioning.message.common.ResourceClassUtil;

import org.apache.commons.lang.Validate;
import org.bouncycastle.jce.PKCS10CertificationRequest;

/**
 * Builder for 'Certificate Issuance Request'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1</a>
 */
public class CertificateIssuanceRequestCmsBuilder extends ProvisioningCmsObjectBuilder {
    private static final XStreamXmlSerializer<CertificateIssuanceRequestPayloadWrapper> SERIALIZER = new CertificateIssuanceRequestPayloadWrapperSerializerBuilder().build();

    private String className;
    private String[] asn;
    private String[] ipv4ResourceSet;
    private String[] ipv6ResourceSet;
    private PKCS10CertificationRequest certificateRequest;

    public CertificateIssuanceRequestCmsBuilder withClassName(String className) {
        this.className = className;
        return this;
    }

    public CertificateIssuanceRequestCmsBuilder withAllocatedAsn(String... asn) {
        this.asn = asn;
        return this;
    }

    public CertificateIssuanceRequestCmsBuilder withIpv4ResourceSet(String... ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
        return this;
    }

    public CertificateIssuanceRequestCmsBuilder withIpv6ResourceSet(String... ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
        return this;
    }


    public CertificateIssuanceRequestCmsBuilder withCertificateRequest(PKCS10CertificationRequest certificateRequest) {
        this.certificateRequest = certificateRequest;
        return this;
    }

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        CertificateIssuanceRequestPayload content = new CertificateIssuanceRequestPayload()
                .setClassName(className)
                .setAllocatedAsn(asn)
                .setAllocatedIpv4(ipv4ResourceSet)
                .setAllocatedIpv6(ipv6ResourceSet)
                .setCertificate(certificateRequest);

        CertificateIssuanceRequestPayloadWrapper payload = new CertificateIssuanceRequestPayloadWrapper(sender, recipient, content);

        return SERIALIZER.serialize(payload);
    }

    @Override
    protected void onValidateFields() {
        Validate.notNull(className, "No className provided");
        Validate.isTrue(ResourceClassUtil.validateAsn(asn), "AS numbers should not start with AS");
        Validate.notNull(certificateRequest);
    }
}
