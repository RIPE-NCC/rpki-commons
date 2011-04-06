package net.ripe.commons.provisioning.message.list.response;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.list.response.ResourceClass;
import net.ripe.commons.provisioning.message.list.response.ResourceClassBuilder;
import net.ripe.commons.provisioning.message.list.response.ResourceClassCmsBuilder;
import net.ripe.commons.provisioning.message.list.response.ResourceClassPayload;
import net.ripe.commons.provisioning.message.list.response.ResourceClassPayloadWrapper;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

import java.net.URISyntaxException;
import java.util.List;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.*;

public class ListResponseCmsBuilderTest {
    
    private DateTime validityNotAfter = new DateTime(2011, 1, 1, 23, 58, 23, 12).withZone(DateTimeZone.UTC);
    private ResourceClassCmsBuilder builder;

    @Before
    public void setUp() {
        // using the list_response type for testing
        builder = new ResourceClassCmsBuilder(PayloadMessageType.list_response);
    }

    @Test
    public void shouldBuildValidListResponsePayload() throws URISyntaxException {
        // given
        builder.withClassName("a classname");
        builder.withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());
        builder.withCertificateAuthorityUri("rsync://localhost/some/where", "http://some/other");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withRecipient("recipient");
        builder.withAllocatedAsn("1234", "456");
        builder.withIpv4ResourceSet("192.168.0.0/24");
        builder.withIpv6ResourceSet("2001:0DB8::/48", "2001:0DB8:002::-2001:0DB8:005::");
        builder.withValidityNotAfter(validityNotAfter);
        builder.withSiaHeadUri("rsync://some/where");
        builder.withResourceSet(new ResourceClassBuilder()
                .withAllocatedAsn("123")
                .withAllocatedIpv4("10.0.0.0/8")
                .withAllocatedIpv6("2001:0DB8::/48")
                .withIssuerCertificatePublicationLocation("rsync://jaja/jja")
                .withCertificate(ProvisioningObjectMother.X509_CA)
                .build());
        builder.withIssuer(ProvisioningObjectMother.X509_CA);

        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        ResourceClassPayloadWrapper wrapper = (ResourceClassPayloadWrapper) parser.getPayloadWrapper();

        assertEquals("CN=test", wrapper.getSender());
        assertEquals("recipient", wrapper.getRecipient());

        ResourceClassPayload payload = wrapper.getPayloadClass();
        assertEquals("http://some/other", payload.getCertificateAuthorityUri()[1]);
        assertEquals("a classname", payload.getClassName());
        assertEquals("192.168.0.0/24", payload.getIpv4ResourceSet()[0]);
        assertEquals("2001:0DB8:002::-2001:0DB8:005::", payload.getIpv6ResourceSet()[1]);
        assertEquals(validityNotAfter, payload.getValidityNotAfter());
        assertEquals("rsync://some/where", payload.getSiaHeadUri());

        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), payload.getIssuer().getEncoded());

        List<ResourceClass> resourceClasses = payload.getResourceClasses();
        assertEquals(1, resourceClasses.size());
        ResourceClass resourceClass = resourceClasses.get(0);
        assertEquals("rsync://jaja/jja", resourceClass.getIssuerCertificatePublicationLocation()[0]);
        assertEquals("123", resourceClass.getAllocatedAsn()[0]);
        assertEquals("10.0.0.0/8", resourceClass.getAllocatedIpv4()[0]);
        assertEquals("2001:0DB8::/48", resourceClass.getAllocatedIpv6()[0]);
        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), resourceClass.getCertificate().getEncoded());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutRsyncURI() throws URISyntaxException {
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri("http://some/other");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withRecipient("recipient");

        builder.build(EE_KEYPAIR.getPrivate());
    }
}
