package net.ripe.commons.provisioning.payload.revocation.request;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.regex.Pattern;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.certification.util.KeyPairUtil;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;

import org.junit.Test;
import org.xml.sax.SAXException;


public class CertificateRevocationRequestPayloadBuilderTest {

    private static final XStreamXmlSerializer<CertificateRevocationRequestPayload> SERIALIZER = new CertificateRevocationRequestPayloadSerializerBuilder().build();

    public static final CertificateRevocationRequestPayload TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD = createCertificateRevocationRequestPayload();

    private static CertificateRevocationRequestPayload createCertificateRevocationRequestPayload() {
        CertificateRevocationRequestPayloadBuilder builder = new CertificateRevocationRequestPayloadBuilder();
        builder.withClassName("a classname");
        builder.withPublicKey(ProvisioningObjectMother.X509_CA.getPublicKey());
        return builder.build();
    }

    @Test
    public void shouldBuildValidRevocationCms() throws Exception {
        assertEquals("sender", TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD.getSender());
        assertEquals("recipient", TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD.getRecipient());

        CertificateRevocationKeyElement payloadContent = TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD.getKeyElement();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals(KeyPairUtil.getEncodedKeyIdentifier(ProvisioningObjectMother.X509_CA.getPublicKey()), payloadContent.getPublicKeyHash());
    }

    @Test
    public void shouldProduceXmlConformStandard() {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD);

        String expectedXmlRegex =
            "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" +
            "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"revoke\">" + "\n" +
            "  <key class_name=\"a classname\" ski=\"[^\"]*\"/>" + "\n" +
            "</message>";

        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }


}
