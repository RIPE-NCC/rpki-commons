package net.ripe.commons.provisioning.message.issue.request;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.message.RelaxNgSchemaValidator;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import net.ripe.ipresource.IpResourceSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.regex.Pattern;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.*;

public class CertificateIssuanceRequestCmsBuilderTest {
    
    private CertificateIssuanceRequestCmsBuilder subject;
    private PKCS10CertificationRequest pkcs10Request;

    @Before
    public void given() throws Exception {
        pkcs10Request = ProvisioningObjectMother.generatePkcs10CertificationRequest(512, "RSA", "SHA1withRSA", "BC");
        
        subject = new CertificateIssuanceRequestCmsBuilder();
        subject.withClassName("a classname");
        subject.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        subject.withRecipient("recipient");
        subject.withAllocatedAsn(IpResourceSet.parse("1234,456"));
        subject.withIpv4ResourceSet(IpResourceSet.parse("10.0.0.0/8"));
        subject.withIpv6ResourceSet(IpResourceSet.parse("2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::"));
        subject.withCertificateRequest(pkcs10Request);
        subject.withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());
    }
    
    @Test
    public void shouldBuildValidListResponsePayload() {

        // when
        ProvisioningCmsObject cmsObject = subject.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("validationlocation", cmsObject.getEncoded());

        CertificateIssuanceRequestPayload payloadWrapper = (CertificateIssuanceRequestPayload) parser.getPayloadWrapper();

        assertEquals("CN=test", payloadWrapper.getSender());
        assertEquals("recipient", payloadWrapper.getRecipient());

        CertificateIssuanceRequestElement payloadContent = payloadWrapper.getRequestElement();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals(IpResourceSet.parse("456,1234"), payloadContent.getAllocatedAsn());
        assertArrayEquals(pkcs10Request.getEncoded(), payloadContent.getCertificate().getEncoded());
        assertEquals(IpResourceSet.parse("10.0.0.0/8"), payloadContent.getAllocatedIpv4());
        assertEquals(IpResourceSet.parse("2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::"), payloadContent.getAllocatedIpv6());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1
    @Test
    public void shouldUsePayloadXmlConformDraft() {
        String actualXml = subject.serializePayloadWrapper("sender", "recipient");
        
        String expectedXmlRegex = "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" +
                                  "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"issue\">" + "\n" +
                                  "  <request class_name=\"a classname\" req_resource_set_as=\"456,1234\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:db8::/48,2001:db8:2::-2001:db8:5::\">[^<]*</request>" + "\n" +
                                  "</message>";

        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutCertificate() throws Exception {
        // given
        CertificateIssuanceRequestCmsBuilder builder = new CertificateIssuanceRequestCmsBuilder();
        builder.withClassName("a classname");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withRecipient("recipient");
        builder.withAllocatedAsn(IpResourceSet.parse("1234,456"));

        // when
        builder.build(EE_KEYPAIR.getPrivate());
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = subject.serializePayloadWrapper("sender", "recipient");

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }


}
