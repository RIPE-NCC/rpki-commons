package net.ripe.commons.provisioning.message.issue.response;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.URISyntaxException;
import java.util.regex.Pattern;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.common.CertificateElement;
import net.ripe.commons.provisioning.message.common.CertificateElementBuilder;
import net.ripe.commons.provisioning.message.common.GenericClassElementBuilder;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;


public class CertificateIssuanceResponseCmsBuilderTest {

    private DateTime validityNotAfter = new DateTime(2011, 1, 1, 23, 58, 23, 12).withZone(DateTimeZone.UTC);
    private CertificateIssuanceResponseCmsBuilder builder;

    @Before
    public void given() {

        // given
        CertificateElement certificateElement = new CertificateElementBuilder().withAllocatedAsn("123").withAllocatedIpv4("10.0.0.0/8")
                .withAllocatedIpv6("2001:0DB8::/48").withIssuerCertificatePublicationLocation("rsync://jaja/jja")
                .withCertificate(ProvisioningObjectMother.X509_CA).build();

        GenericClassElementBuilder classElementBuilder = new GenericClassElementBuilder().withClassName("a classname")
                .withCertificateAuthorityUri("rsync://localhost/some/where", "http://some/other").withAllocatedAsn("1234", "456")
                .withIpv4ResourceSet("192.168.0.0/24").withIpv6ResourceSet("2001:0DB8::/48", "2001:0DB8:002::-2001:0DB8:005::")
                .withValidityNotAfter(validityNotAfter).withSiaHeadUri("rsync://some/where").withCertificateElements(certificateElement)
                .withIssuer(ProvisioningObjectMother.X509_CA);

        builder = new CertificateIssuanceResponseCmsBuilder();
        builder.withClassElement(classElementBuilder.buildCertificateIssuanceResponseClassElement());
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
    }

    @Test
    public void shouldBuildValidCIResponsePayload() throws URISyntaxException {
        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("validationLocation", cmsObject.getEncoded());
        CertificateIssuanceResponsePayloadWrapper wrapper = (CertificateIssuanceResponsePayloadWrapper) parser.getPayloadWrapper();

        assertEquals(PayloadMessageType.issue_response, wrapper.getType());
    }

    // see: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2
    @Test
    public void shouldHavePayloadXmlConformStandard() {
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");
        
        String expectedXmlRegex = 
        "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" +
        "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"issue_response\">" + "\n" +
        "  <class class_name=\"a classname\" cert_url=\"rsync://localhost/some/where,http://some/other\" resource_set_as=\"1234,456\" resource_set_ipv4=\"192.168.0.0/24\" resource_set_ipv6=\"2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::\" resource_set_notafter=\"2011-01-01T22:58:23.012Z\" suggested_sia_head=\"rsync://some/where\">\n" +
        "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:0DB8::/48\">[^<]*</certificate>" + "\n" +
        "    <issuer>[^<]*</issuer>" + "\n" +
        "  </class>" + "\n" +
        "</message>";
        
        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }

}
