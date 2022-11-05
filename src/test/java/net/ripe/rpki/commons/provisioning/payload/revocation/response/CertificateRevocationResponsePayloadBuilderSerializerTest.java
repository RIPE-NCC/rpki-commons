package net.ripe.rpki.commons.provisioning.payload.revocation.response;

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


public class CertificateRevocationResponsePayloadBuilderSerializerTest {

    private static final XmlSerializer<CertificateRevocationResponsePayload> SERIALIZER = new CertificateRevocationResponsePayloadSerializer();

    public static final CertificateRevocationResponsePayload TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD = createCertificateRevocationResponsePayload();


    public static CertificateRevocationResponsePayload createCertificateRevocationResponsePayload() {
        CertificateRevocationResponsePayloadBuilder builder = new CertificateRevocationResponsePayloadBuilder();
        builder.withClassName("a classname");
        builder.withPublicKey(ProvisioningObjectMother.X509_CA.getPublicKey());
        return builder.build();
    }

    @Test
    public void shouldBuildValidRevocationCms() {
        assertEquals("sender", TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD.getSender());
        assertEquals("recipient", TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD.getRecipient());

        CertificateRevocationKeyElement payloadContent = TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD.getKeyElement();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals(KeyPairUtil.getEncodedKeyIdentifier(ProvisioningObjectMother.X509_CA.getPublicKey()), payloadContent.getPublicKeyHash());
    }

    @Test
    public void shouldProduceXmlConformStandard() throws IdentitySerializerException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD);

        Pattern expectedXmlRegex = Pattern.compile(
                "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>\n" +
                        "<message\\s+xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\"\\s+recipient=\"recipient\"\\s+sender=\"sender\"\\s+type=\"revoke_response\"\\s+version=\"1\">\n" +
                        "   <key\\s+class_name=\"a classname\"\\s+ski=\"[^\"]*\"/>\n" +
                        "</message>\n",
                Pattern.DOTALL
        );

        assertTrue("actual xml: " + actualXml, expectedXmlRegex.matcher(actualXml).matches());
    }

    @Test
    public void shouldDeserializeXml() throws IdentitySerializerException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD);
        CertificateRevocationResponsePayload deserialized = SERIALIZER.deserialize(actualXml);
        assertEquals(TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD, deserialized);
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException, IdentitySerializerException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
