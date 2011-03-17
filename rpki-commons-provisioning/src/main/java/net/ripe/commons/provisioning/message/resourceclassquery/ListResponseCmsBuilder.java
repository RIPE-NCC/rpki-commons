package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.security.PrivateKey;
import java.util.Arrays;
import java.util.List;

public class ListResponseCmsBuilder extends ProvisioningCmsObjectBuilder {

    private static final XStreamXmlSerializer<ListResponsePayload> SERIALIZER = new ListResponsePayloadSerializerBuilder().build();

    private String className;
    private String[] certificateAuthorityUri;
    private String sender;
    private String recipient;
    private String[] asn;
    private String[] ipv4ResourceSet;
    private String[] ipv6ResourceSet;
    private DateTime validityNotAfter;
    private String siaHeadUri;
    private List<ResourceSet> resourceSets;
    private X509ResourceCertificate issuer;

    // TODO remove after parser decodes the content - strictly for junit testing
    public String xml;

    public ListResponseCmsBuilder withSender(String sender) {
        this.sender = sender;
        return this;
    }

    public ListResponseCmsBuilder withRecipient(String recipient) {
        this.recipient = recipient;
        return this;
    }

    public ListResponseCmsBuilder withClassName(String className) {
        this.className = className;
        return this;
    }

    public ListResponseCmsBuilder withAllocatedAsn(String... asn) {
        this.asn = asn;
        return this;
    }

    public ListResponseCmsBuilder withCertificateAuthorityUri(String... caUri) {
        this.certificateAuthorityUri = caUri;
        return this;
    }

    public ListResponseCmsBuilder withIpv4ResourceSet(String... ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
        return this;
    }

    public ListResponseCmsBuilder withIpv6ResourceSet(String... ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
        return this;
    }

    public ListResponseCmsBuilder withValidityNotAfter(DateTime notAfter) {
        this.validityNotAfter = notAfter;
        return this;
    }

    public ListResponseCmsBuilder withSiaHeadUri(String siaHead) {
        this.siaHeadUri = siaHead;
        return this;
    }

    public ListResponseCmsBuilder withResourceSet(ResourceSet... resourceSets) {
        this.resourceSets = Arrays.asList(resourceSets);
        return this;
    }

    public ListResponseCmsBuilder withIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
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
        Validate.notNull(validityNotAfter, "Validity not after is required");
        Validate.isTrue(validityNotAfter.getZone().equals(DateTimeZone.UTC), "Validity time must be in UTC timezone");
        Validate.isTrue(ResourceClassUtil.validateAsn(asn), "AS numbers should not start with AS");
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(certificateAuthorityUri);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(issuer, "issuer certificate is required");
    }

    private String createSerializedPayload() {
        ListResponsePayloadClass payloadClass = new ListResponsePayloadClass()
                .setClassName(className)
                .setCertificateAuthorityUri(certificateAuthorityUri)
                .setResourceSetAsNumbers(asn)
                .setIpv4ResourceSet(ipv4ResourceSet)
                .setIpv6ResourceSet(ipv6ResourceSet)
                .setValidityNotAfter(validityNotAfter)
                .setSiaHeadUri(siaHeadUri)
                .setResourceSets(resourceSets)
                .setIssuer(issuer);

        ListResponsePayload payload = new ListResponsePayload(sender, recipient, payloadClass);

        xml = SERIALIZER.serialize(payload);
        return xml;
    }

}
