package net.ripe.commons.provisioning.message.list.response;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.net.URISyntaxException;
import java.util.List;
import java.util.regex.Pattern;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.message.common.CertificateElement;
import net.ripe.commons.provisioning.message.common.CertificateElementBuilder;
import net.ripe.commons.provisioning.message.common.GenericClassElementBuilder;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

public class ResourceClassListResponseCmsBuilderTest {
    
    private DateTime validityNotAfter = new DateTime(2011, 1, 1, 23, 58, 23, 12).withZone(DateTimeZone.UTC);
    private ResourceClassListResponseCmsBuilder builder;

    @Before
    public void given() {
        builder = new ResourceClassListResponseCmsBuilder();
        CertificateElement certificateElement = new CertificateElementBuilder().withAllocatedAsn("123")
                                                                               .withAllocatedIpv4("10.0.0.0/8")
                                                                               .withAllocatedIpv6("2001:0DB8::/48")
                                                                               .withIssuerCertificatePublicationLocation("rsync://jaja/jja")
                                                                               .withCertificate(ProvisioningObjectMother.X509_CA).build();
        
        GenericClassElementBuilder classElementBuilder = new GenericClassElementBuilder()
                           .withClassName("a classname")
                           .withCertificateAuthorityUri("rsync://localhost/some/where", "http://some/other")
                           .withAllocatedAsn("1234", "456")
                           .withIpv4ResourceSet("192.168.0.0/24")
                           .withIpv6ResourceSet("2001:0DB8::/48", "2001:0DB8:002::-2001:0DB8:005::")
                           .withValidityNotAfter(validityNotAfter)
                           .withSiaHeadUri("rsync://some/where")
                           .withCertificateElements(certificateElement)
                           .withIssuer(ProvisioningObjectMother.X509_CA);
        
        builder.addClassElement(classElementBuilder.buildResourceClassListResponseClassElement());
        
        classElementBuilder.withClassName("class2");
        classElementBuilder.withCertificateElements(certificateElement, certificateElement);
        builder.addClassElement(classElementBuilder.buildResourceClassListResponseClassElement());
        
        builder.withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withRecipient("recipient");
    }

    @Test
    public void shouldBuildValidListResponsePayload() throws URISyntaxException {
        // given

        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        ResourceClassListResponsePayloadWrapper wrapper = (ResourceClassListResponsePayloadWrapper) parser.getPayloadWrapper();

        assertEquals("CN=test", wrapper.getSender());
        assertEquals("recipient", wrapper.getRecipient());

        ResourceClassListResponseClassElement firstClassElement = wrapper.getClassElements().get(0);
        assertEquals("http://some/other", firstClassElement.getCertificateAuthorityUri()[1]);
        assertEquals("a classname", firstClassElement.getClassName());
        assertEquals("192.168.0.0/24", firstClassElement.getIpv4ResourceSet()[0]);
        assertEquals("2001:0DB8:002::-2001:0DB8:005::", firstClassElement.getIpv6ResourceSet()[1]);
        assertEquals(validityNotAfter, firstClassElement.getValidityNotAfter());
        assertEquals("rsync://some/where", firstClassElement.getSiaHeadUri());

        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), firstClassElement.getIssuer().getEncoded());

        List<CertificateElement> certificateElements = firstClassElement.getCertificateElements();
        assertEquals(1, certificateElements.size());
        CertificateElement certificateElement = certificateElements.get(0);
        assertEquals("rsync://jaja/jja", certificateElement.getIssuerCertificatePublicationLocation()[0]);
        assertEquals("123", certificateElement.getAllocatedAsn()[0]);
        assertEquals("10.0.0.0/8", certificateElement.getAllocatedIpv4()[0]);
        assertEquals("2001:0DB8::/48", certificateElement.getAllocatedIpv6()[0]);
        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), certificateElement.getCertificate().getEncoded());
    }
    
    
    // see: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2
    @Test
    public void shouldCreatePayloadXmlConformDraft() {
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");

        String expectedXmlRegex = "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" +
                                  "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"list_response\">" + "\n" +
                                  "  <class class_name=\"a classname\" cert_url=\"rsync://localhost/some/where,http://some/other\" resource_set_as=\"1234,456\" resource_set_ipv4=\"192.168.0.0/24\" resource_set_ipv6=\"2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::\" resource_set_notafter=\"2011-01-01T22:58:23.012Z\" suggested_sia_head=\"rsync://some/where\">\n" +
                                  "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:0DB8::/48\">[^<]*</certificate>" + "\n" +
                                  "    <issuer>[^<]*</issuer>" + "\n" +
                                  "  </class>" + "\n" +
                                  "  <class class_name=\"class2\" cert_url=\"rsync://localhost/some/where,http://some/other\" resource_set_as=\"1234,456\" resource_set_ipv4=\"192.168.0.0/24\" resource_set_ipv6=\"2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::\" resource_set_notafter=\"2011-01-01T22:58:23.012Z\" suggested_sia_head=\"rsync://some/where\">\n" +
                                  "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:0DB8::/48\">[^<]*</certificate>" + "\n" +
                                  "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:0DB8::/48\">[^<]*</certificate>" + "\n" +
                                  "    <issuer>[^<]*</issuer>" + "\n" +
                                  "  </class>" + "\n" +
                                  "</message>";
        
        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }

}
