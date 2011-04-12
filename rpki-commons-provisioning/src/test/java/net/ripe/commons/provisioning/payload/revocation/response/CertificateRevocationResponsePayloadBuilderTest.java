package net.ripe.commons.provisioning.payload.revocation.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.certification.util.KeyPairUtil;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;
import net.ripe.commons.provisioning.payload.revocation.response.CertificateRevocationResponsePayload;
import net.ripe.commons.provisioning.payload.revocation.response.CertificateRevocationResponsePayloadBuilder;
import net.ripe.commons.provisioning.payload.revocation.response.CertificateRevocationResponsePayloadSerializerBuilder;

import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class CertificateRevocationResponsePayloadBuilderTest {

    private static final XStreamXmlSerializer<CertificateRevocationResponsePayload> SERIALIZER = new CertificateRevocationResponsePayloadSerializerBuilder().build();

    private CertificateRevocationResponsePayloadBuilder builder;

    private CertificateRevocationResponsePayload payload;

    @Before
    public void given() {
        builder = new CertificateRevocationResponsePayloadBuilder();
        builder.withClassName("a classname");
        builder.withPublicKey(ProvisioningObjectMother.X509_CA.getPublicKey());
        builder.withSender("sender");
        builder.withRecipient("recipient");
        payload = builder.build();
    }

    @Test
    public void shouldBuildValidRevocationCms() throws Exception {
        assertEquals("sender", payload.getSender());
        assertEquals("recipient", payload.getRecipient());

        CertificateRevocationKeyElement payloadContent = payload.getKeyElement();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals(KeyPairUtil.getEncodedKeyIdentifier(ProvisioningObjectMother.X509_CA.getPublicKey()), payloadContent.getPublicKeyHash());
    }

    @Test
    public void shouldProduceXmlConformStandard() {
        String actualXml = SERIALIZER.serialize(payload);

        String expectedXmlRegex =
                "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" +
                        "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"revoke_response\">" + "\n" +
                        "  <key class_name=\"a classname\" ski=\"[^\"]*\"/>" + "\n" +
                        "</message>";

        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }


    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(payload);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
