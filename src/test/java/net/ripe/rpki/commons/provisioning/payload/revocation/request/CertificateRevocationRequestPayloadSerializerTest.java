package net.ripe.rpki.commons.provisioning.payload.revocation.request;

import net.ripe.rpki.commons.crypto.util.KeyPairUtil;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.provisioning.identity.IdentitySerializerException;
import net.ripe.rpki.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.rpki.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;
import net.ripe.rpki.commons.xml.XmlSerializer;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class CertificateRevocationRequestPayloadSerializerTest {

    private static final XmlSerializer<CertificateRevocationRequestPayload> SERIALIZER = new CertificateRevocationRequestPayloadSerializer();

    public static final CertificateRevocationRequestPayload TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD = createCertificateRevocationRequestPayload();

    private static CertificateRevocationRequestPayload createCertificateRevocationRequestPayload() {
        CertificateRevocationRequestPayloadBuilder builder = new CertificateRevocationRequestPayloadBuilder();
        builder.withClassName("a classname");
        builder.withPublicKey(ProvisioningObjectMother.X509_CA.getPublicKey());
        return builder.build();
    }

    @Test
    public void shouldBuildValidRevocationCms() {
        assertEquals("sender", TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD.getSender());
        assertEquals("recipient", TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD.getRecipient());

        CertificateRevocationKeyElement payloadContent = TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD.getKeyElement();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals(KeyPairUtil.getEncodedKeyIdentifier(ProvisioningObjectMother.X509_CA.getPublicKey()), payloadContent.getPublicKeyHash());
    }

    @Test
    public void shouldProduceXmlConformStandard() throws IdentitySerializerException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD);

        Pattern expectedXmlRegex = Pattern.compile(
                "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>\n" +
                        "<message\\s+xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\"\\s+recipient=\"recipient\"\\s+sender=\"sender\"\\s+type=\"revoke\"\\s+version=\"1\">\n" +
                        "   <key\\s+class_name=\"a classname\"\\s+ski=\"[^\"]*\"/>\n" +
                        "</message>\n",
                Pattern.DOTALL
        );

        assertTrue("actual xml:" + actualXml, expectedXmlRegex.matcher(actualXml).matches());
    }

    @Test
    public void shouldDeserializeXml() throws IdentitySerializerException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD);
        CertificateRevocationRequestPayload deserialized = SERIALIZER.deserialize(actualXml);
        assertEquals(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD, deserialized);
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException, IdentitySerializerException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }


}
