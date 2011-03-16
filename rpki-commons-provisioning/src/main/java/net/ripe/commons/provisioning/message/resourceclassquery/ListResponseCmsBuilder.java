package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.ipresource.IpRange;
import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;

import java.net.URI;
import java.security.PrivateKey;

public class ListResponseCmsBuilder extends ProvisioningCmsObjectBuilder {

    private static final XStreamXmlSerializer<ListResponsePayload> SERIALIZER = new ListResponsePayloadSerializerBuilder().build();

    private String className;
    private URI[] certificateAuthorityUri;
    private String sender;
    private String recipient;
    private String[] asn;
    private IpRange[] ipv4ResourceSet;
    private IpRange[] ipv6ResourceSet;
    private DateTime validityNotAfter;
    private String publicationPoint;

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

    public ListResponseCmsBuilder withCertificateAuthorityUri(URI... caUri) {
        this.certificateAuthorityUri = caUri;
        return this;
    }

    public ListResponseCmsBuilder withIpv4ResourceSet(IpRange... ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
        return this;
    }

    public ListResponseCmsBuilder withIpv6ResourceSet(IpRange... ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
        return this;
    }

    public ListResponseCmsBuilder withValidityNotAfter(DateTime notAfter) {
        this.validityNotAfter = notAfter;
        return this;
    }

    public ListResponseCmsBuilder withPublicationPoint(String publicationPoint) {
        this.publicationPoint = publicationPoint;
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

        boolean rsyncUriFound = findRsyncUri();
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");
    }

    private String createSerializedPayload() {
        ListResponsePayloadClass payloadClassClass = new ListResponsePayloadClass()
                .setClassName(className)
                .setCertificateAuthorityUri(certificateAuthorityUri)
                .setResourceSetAsNumbers(asn)
                .setResourceSetIpv4(ipv4ResourceSet)
                .setResourceSetIpv6(ipv6ResourceSet)
                .setResourceSetNotAfter(validityNotAfter)
                .setSuggestedSiaHeadUri(publicationPoint);

        ListResponsePayload payload = new ListResponsePayload(sender, recipient, PayloadMessageType.list_response, payloadClassClass);

        xml = SERIALIZER.serialize(payload);
//        System.out.println(xml);
//        System.out.println(SERIALIZER.deserialize(xml).getPayloadClass().getClassName());
        return xml;
    }

    private boolean findRsyncUri() {
        boolean rsyncUriFound = false;

        for (URI uri : certificateAuthorityUri) {
            if (uri.getScheme().toLowerCase().startsWith("rsync")) {
                rsyncUriFound = true;
                break;
            }
        }
        return rsyncUriFound;
    }
}
