package net.ripe.commons.provisioning.payload.list.request;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.commons.provisioning.payload.list.request.ResourceClassListQueryPayload;
import net.ripe.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder;
import net.ripe.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadSerializerBuilder;

import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ResourceClassListQueryPayloadBuilderTest {

    private static final XStreamXmlSerializer<ResourceClassListQueryPayload> SERIALIZER = new ResourceClassListQueryPayloadSerializerBuilder().build();

    @Test
    public void shouldCreateParsableProvisioningObject() throws IOException {
        // given
        ResourceClassListQueryPayloadBuilder builder = new ResourceClassListQueryPayloadBuilder();
        builder.withRecipient("recipient");
        builder.withSender("sender");

        // when
        String xml = builder.build();

        // then
        ResourceClassListQueryPayload payload = SERIALIZER.deserialize(xml);

        assertEquals("sender", payload.getSender());
        assertEquals("recipient", payload.getRecipient());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    @Test
    public void shouldCreateXmlConformDraft() {
        ResourceClassListQueryPayloadBuilder builder = new ResourceClassListQueryPayloadBuilder();
        String expectedXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "\n" +
                "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"list\"/>";

        String actualXml = builder.serializePayloadWrapper("sender", "recipient");
        assertEquals(expectedXml, actualXml);
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutRecipient() throws IOException {
        ResourceClassListQueryPayloadBuilder payloadBuilder = new ResourceClassListQueryPayloadBuilder();
        payloadBuilder.withRecipient("recipient");
        payloadBuilder.build();
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutSender() throws IOException {
        ResourceClassListQueryPayloadBuilder payloadBuilder = new ResourceClassListQueryPayloadBuilder();
        payloadBuilder.build();
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        ResourceClassListQueryPayloadBuilder builder = new ResourceClassListQueryPayloadBuilder();
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }

}
