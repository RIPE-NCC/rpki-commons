package net.ripe.commons.provisioning.message.list.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.common.CommonCmsBuilder;

import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.util.Arrays;
import java.util.List;

public class ResourceClassCmsBuilder extends CommonCmsBuilder {

    private static final XStreamXmlSerializer<ResourceClassPayloadWrapper> SERIALIZER = new ResourceClassPayloadWrapperSerializerBuilder().build();

    private String className;
    private String[] certificateAuthorityUri;
    private String[] asn;
    private String[] ipv4ResourceSet;
    private String[] ipv6ResourceSet;
    private List<ResourceClass> resourceClasses;
    private X509ResourceCertificate issuer;
    private DateTime validityNotAfter;
    private String siaHeadUri;
    private PayloadMessageType payloadMessageType;

    protected ResourceClassCmsBuilder(PayloadMessageType payloadMessageType) {
        this.payloadMessageType = payloadMessageType;
    }

    public void withValidityNotAfter(DateTime notAfter) {
        this.validityNotAfter = notAfter;
    }

    public void withSiaHeadUri(String siaHead) {
        this.siaHeadUri = siaHead;
    }

    public void withClassName(String className) {
        this.className = className;
    }

    public void withAllocatedAsn(String... asn) {
        this.asn = asn;
    }

    public void withCertificateAuthorityUri(String... caUri) {
        this.certificateAuthorityUri = caUri;
    }

    public void withIpv4ResourceSet(String... ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
    }

    public void withIpv6ResourceSet(String... ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
    }

    public void withResourceSet(ResourceClass... resourceClasses) {
        this.resourceClasses = Arrays.asList(resourceClasses);
    }

    public void withIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
    }

    @Override
    protected final void onValidateFields() {
        Validate.notNull(className, "No className provided");
        Validate.isTrue(ResourceClassUtil.validateAsn(asn), "AS numbers should not start with AS");
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(certificateAuthorityUri);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(issuer, "issuer certificate is required");

        Validate.notNull(validityNotAfter, "Validity not after is required");
        Validate.isTrue(validityNotAfter.getZone().equals(DateTimeZone.UTC), "Validity time must be in UTC timezone");

        Validate.notNull(payloadMessageType, "Message type is required");
    }

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        ResourceClassPayload resourceClassPayload = new ResourceClassPayload();
        resourceClassPayload.setClassName(className);
        resourceClassPayload.setCertificateAuthorityUri(certificateAuthorityUri);
        resourceClassPayload.setResourceSetAsNumbers(asn);
        resourceClassPayload.setIpv4ResourceSet(ipv4ResourceSet);
        resourceClassPayload.setIpv6ResourceSet(ipv6ResourceSet);
        resourceClassPayload.setResourceClasses(resourceClasses);
        resourceClassPayload.setIssuer(issuer);
        resourceClassPayload.setValidityNotAfter(validityNotAfter);
        resourceClassPayload.setSiaHeadUri(siaHeadUri);

        ResourceClassPayloadWrapper wrapper = new ResourceClassPayloadWrapper(sender, recipient, resourceClassPayload, payloadMessageType);

        return SERIALIZER.serialize(wrapper);
    }
}
