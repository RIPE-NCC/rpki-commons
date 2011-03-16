package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.ipresource.IpRange;
import org.joda.time.DateTime;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ListResponseCmsBuilderTest {

    @Test
    public void shouldBuildValidListResponsePayload() throws URISyntaxException {
        // given
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(new URI("rsync://localhost/some/where"), new URI("http://some/other"));
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");
        builder.withAllocatedAsn("AS1234", "AS456");
        builder.withIpv4ResourceSet(IpRange.parse("192.168.0.0/24"));
        builder.withIpv6ResourceSet(IpRange.parse("2001:0DB8::/48"), IpRange.parse("2001:0DB8:002::-2001:0DB8:005::"));
        builder.withValidityNotAfter(new DateTime(2011, 1, 1, 23, 58, 23, 12));
        builder.withPublicationPoint("rsync://some/where");
        builder.withResourceSet(new ResourceSetBuilder().withIpv4ResourceSet("192.168.0.0/2 4").withCertificateAuthorityUri("rsync://jaja/jja").withCertificate(ProvisioningObjectMother.X509_CA).build());

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace with decoded from cms obj

        XStreamXmlSerializer<ListResponsePayload> serializer = new ListResponsePayloadSerializerBuilder().build();
        ListResponsePayload deserializedPayload = serializer.deserialize(builder.xml);

        System.out.println(builder.xml);

        System.out.println(deserializedPayload);

        assertEquals("sender", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());
        assertEquals("a classname", deserializedPayload.getPayloadClass().getClassName());
    }


    @Test
    public void shouldBuildValidListResponsePayloadWithoutIpv4OrIpv6() throws URISyntaxException {

        // given
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(new URI("rsync://localhost/some/where"), new URI("http://some/other"));
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");
        builder.withValidityNotAfter(new DateTime(2011, 1, 1, 23, 58, 23, 12));

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
        builder.withCertificateAuthorityUri(new URI("rsync://localhost/some/where"), new URI("http://some/other"));
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");
        builder.withValidityNotAfter(new DateTime(2011, 1, 1, 23, 58, 23, 12));
        builder.build(EE_KEYPAIR.getPrivate());

        // TODO replace with decoded from cms obj
        assertTrue(builder.xml.contains("resource_set_as=\"\""));
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutRsyncURI() throws URISyntaxException {
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(new URI("http://localhost/some/where"));
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");

        builder.build(EE_KEYPAIR.getPrivate());
    }
}