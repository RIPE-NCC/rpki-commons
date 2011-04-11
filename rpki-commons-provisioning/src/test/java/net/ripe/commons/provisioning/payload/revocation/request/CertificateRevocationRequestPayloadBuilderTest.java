package net.ripe.commons.provisioning.payload.revocation.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.certification.util.KeyPairUtil;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.commons.provisioning.payload.revocation.CertificateRevocationKeyElement;
import net.ripe.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayload;
import net.ripe.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayloadBuilder;
import net.ripe.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayloadSerializerBuilder;

import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class CertificateRevocationRequestPayloadBuilderTest {

    private static final XStreamXmlSerializer<CertificateRevocationRequestPayload> SERIALIZER = new CertificateRevocationRequestPayloadSerializerBuilder().build();

    private CertificateRevocationRequestPayloadBuilder builder;

    @Before
    public void given() {
        builder = new CertificateRevocationRequestPayloadBuilder();
        builder.withClassName("a classname");
        builder.withRecipient("recipient");
        builder.withSender("sender");
        builder.withPublicKey(ProvisioningObjectMother.X509_CA.getPublicKey());
    }

    @Test
    public void shouldBuildValidRevocationCms() throws Exception {
        // when
        String xml = builder.build();

        // then
        CertificateRevocationRequestPayload payload = SERIALIZER.deserialize(xml);
        assertEquals("sender", payload.getSender());
        assertEquals("recipient", payload.getRecipient());

        CertificateRevocationKeyElement payloadContent = payload.getKeyElement();
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
