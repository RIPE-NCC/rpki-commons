package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;

import java.net.URISyntaxException;
import java.util.List;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.*;

public class ListResponseCmsBuilderTest {

    private DateTime validityNotAfter  = new DateTime(2011, 1, 1, 23, 58, 23, 12).withZone(DateTimeZone.UTC);

    @Test
    public void shouldBuildValidListResponsePayload() throws URISyntaxException {
        // given
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri("rsync://localhost/some/where", "http://some/other");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");
        builder.withAllocatedAsn("1234", "456");
        builder.withIpv4ResourceSet("192.168.0.0/24");
        builder.withIpv6ResourceSet("2001:0DB8::/48", "2001:0DB8:002::-2001:0DB8:005::");
        builder.withValidityNotAfter(validityNotAfter);
        builder.withSiaHeadUri("rsync://some/where");
        builder.withResourceSet(new ResourceSetBuilder()
                .withAllocatedAsn("123")
                .withAllocatedIpv4("10.0.0.0/8")
                .withAllocatedIpv6("2001:0DB8::/48")
                .withIssuerCertificatePublicationLocation("rsync://jaja/jja")
                .withCertificate(ProvisioningObjectMother.X509_CA)
                .build());
        builder.withIssuer(ProvisioningObjectMother.X509_CA);

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace with decoded from cms obj

        XStreamXmlSerializer<ListResponsePayload> serializer = new ListResponsePayloadSerializerBuilder().build();
        ListResponsePayload deserializedPayload = serializer.deserialize(builder.xml);

        System.out.println(builder.xml);

        assertEquals("sender", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());

        ListResponsePayloadClass payloadClass = deserializedPayload.getPayloadClass();
        assertEquals("http://some/other", payloadClass.getCertificateAuthorityUri()[1]);
        assertEquals("a classname", payloadClass.getClassName());
        assertEquals("192.168.0.0/24", payloadClass.getIpv4ResourceSet()[0]);
        assertEquals("2001:0DB8:002::-2001:0DB8:005::", payloadClass.getIpv6ResourceSet()[1]);
        assertEquals(validityNotAfter, payloadClass.getValidityNotAfter());
        assertEquals("rsync://some/where", payloadClass.getSiaHeadUri());

        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), payloadClass.getIssuer().getEncoded());

        List<ResourceSet> resourceSets = payloadClass.getResourceSets();
        assertEquals(1, resourceSets.size());
        ResourceSet resourceSet = resourceSets.get(0);
        assertEquals("rsync://jaja/jja", resourceSet.getIssuerCertificatePublicationLocation()[0]);
        assertEquals("123", resourceSet.getAllocatedAsn()[0]);
        assertEquals("10.0.0.0/8", resourceSet.getAllocatedIpv4()[0]);
        assertEquals("2001:0DB8::/48", resourceSet.getAllocatedIpv6()[0]);
        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), resourceSet.getCertificate().getEncoded());
//        assertEquals(deserializedPayload.getPayloadClass().getResourceSetAsNumbers());
    }


    @Test
    public void shouldBuildValidListResponsePayloadWithoutIpv4OrIpv6() throws URISyntaxException {

        // given
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri("rsync://localhost/some/where", "http://some/other");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");
        builder.withValidityNotAfter(validityNotAfter);
        builder.withIssuer(ProvisioningObjectMother.X509_CA);

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace with decoded from cms obj
        assertTrue(builder.xml.contains("resource_set_ipv4=\"\""));
        assertTrue(builder.xml.contains("resource_set_ipv6=\"\""));
    }

    @Test
    public void shouldBuildValidListResponsePayloadWithoutAsn() throws URISyntaxException {

        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri("rsync://localhost/some/where", "http://some/other");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");
        builder.withValidityNotAfter(validityNotAfter);
        builder.withIssuer(ProvisioningObjectMother.X509_CA);

        builder.build(EE_KEYPAIR.getPrivate());

        // TODO replace with decoded from cms obj
        assertTrue(builder.xml.contains("resource_set_as=\"\""));
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutRsyncURI() throws URISyntaxException {
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri("http://some/other");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");

        builder.build(EE_KEYPAIR.getPrivate());
    }
}