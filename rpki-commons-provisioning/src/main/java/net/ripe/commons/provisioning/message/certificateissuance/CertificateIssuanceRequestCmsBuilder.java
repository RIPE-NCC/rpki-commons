package net.ripe.commons.provisioning.message.certificateissuance;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import net.ripe.commons.provisioning.message.resourceclassquery.ResourceClassUtil;
import org.apache.commons.lang.Validate;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import java.security.PrivateKey;

public class CertificateIssuanceRequestCmsBuilder extends ProvisioningCmsObjectBuilder {
    private static final XStreamXmlSerializer<CertificateIssuanceRequestPayload> SERIALIZER = new CertificateIssuanceRequestPayloadSerializerBuilder().build();

    private String className;
    private String sender;
    private String recipient;
    private String[] asn;
    private String[] ipv4ResourceSet;
    private String[] ipv6ResourceSet;
    private PKCS10CertificationRequest certificateRequest;


    // TODO remove after parser decodes the content - strictly for junit testing
    public String xml;

    public CertificateIssuanceRequestCmsBuilder withSender(String sender) {
        this.sender = sender;
        return this;
    }

    public CertificateIssuanceRequestCmsBuilder withRecipient(String recipient) {
        this.recipient = recipient;
        return this;
    }

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
    public ProvisioningCmsObject build(PrivateKey privateKey) {
        validateFields();

        String payload = createSerializedPayload();
        withPayloadContent(payload);

        return super.build(privateKey);
    }

    private void validateFields() {
        Validate.notNull(sender, "Sender is required");
        Validate.notNull(recipient, "Recipient is required");
        Validate.notNull(className, "No className provided");
        Validate.isTrue(ResourceClassUtil.validateAsn(asn), "AS numbers should not start with AS");
        Validate.notNull(certificateRequest);
    }

    private String createSerializedPayload() {
        CertificateIssuanceRequestContent content = new CertificateIssuanceRequestContent()
                .setClassName(className)
                .setAllocatedAsn(asn)
                .setAllocatedIpv4(ipv4ResourceSet)
                .setAllocatedIpv6(ipv6ResourceSet)
                .setCertificate(certificateRequest);

        CertificateIssuanceRequestPayload payload = new CertificateIssuanceRequestPayload(sender, recipient, content);

        xml = SERIALIZER.serialize(payload);
        return xml;
    }
}
