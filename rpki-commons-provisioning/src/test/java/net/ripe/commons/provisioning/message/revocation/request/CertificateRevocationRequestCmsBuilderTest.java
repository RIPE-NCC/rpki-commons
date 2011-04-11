package net.ripe.commons.provisioning.message.revocation.request;

import net.ripe.commons.certification.util.KeyPairUtil;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.message.RelaxNgSchemaValidator;
import net.ripe.commons.provisioning.message.revocation.CertificateRevocationKeyElement;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.regex.Pattern;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class CertificateRevocationRequestCmsBuilderTest {

    private CertificateRevocationRequestCmsBuilder builder;

    @Before
    public void given() {
        builder = new CertificateRevocationRequestCmsBuilder();
        builder.withClassName("a classname");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withRecipient("recipient");
        builder.withPublicKey(ProvisioningObjectMother.X509_CA.getPublicKey());
        builder.withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());
    }

    @Test
    public void shouldBuildValidRevocationCms() throws Exception {
        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        CertificateRevocationRequestPayload revocationPayloadWrapper = (CertificateRevocationRequestPayload) parser.getPayloadWrapper();
        assertEquals("CN=test", revocationPayloadWrapper.getSender());
        assertEquals("recipient", revocationPayloadWrapper.getRecipient());

        CertificateRevocationKeyElement payloadContent = revocationPayloadWrapper.getKeyElement();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals(KeyPairUtil.getEncodedKeyIdentifier(ProvisioningObjectMother.X509_CA.getPublicKey()), payloadContent.getPublicKeyHash());
    }

    @Test
    public void shouldProduceXmlConformStandard() {
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");

        String expectedXmlRegex =
            "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" +
            "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"revoke\">" + "\n" +
            "  <key class_name=\"a classname\" ski=\"[^\"]*\"/>" + "\n" +
            "</message>";

        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }


}
