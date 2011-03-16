package net.ripe.commons.provisioning.message.resourceclassquery;

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

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace with decoded from cms obj
        System.out.println(builder.xml);

        assertEquals("<?xml version=\"1.0\" encoding=\"UTF-8\"?><message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"list_response\">\n" +
                "  <class class_name=\"a classname\" cert_url=\"rsync://localhost/some/where,http://some/other\" resource_set_as=\"AS1234,AS456\" resource_set_ipv4=\"192.168.0.0/24\" resource_set_ipv6=\"2001:db8::/48,2001:db8:2::-2001:db8:5::\" resource_set_notafter=\"2011-01-01T22:58:23.012Z\" suggested_sia_head=\"rsync://some/where\"/>\n" +
                "</message>", builder.xml);
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