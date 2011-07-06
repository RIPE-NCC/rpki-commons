package net.ripe.commons.provisioning.payload.list.request;

import static org.junit.Assert.*;

import java.io.IOException;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.RelaxNgSchemaValidator;

import org.junit.Test;
import org.xml.sax.SAXException;

public class ResourceClassListQueryPayloadBuilderTest {

    private static final XStreamXmlSerializer<ResourceClassListQueryPayload> SERIALIZER = new ResourceClassListQueryPayloadSerializerBuilder().build();
    public static final ResourceClassListQueryPayload TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD = createResourceClassListQueryPayload();

    private static ResourceClassListQueryPayload createResourceClassListQueryPayload() {
        ResourceClassListQueryPayloadBuilder builder = new ResourceClassListQueryPayloadBuilder();
        return builder.build();
    }
    
    @Test
    public void shouldCreateParsableProvisioningObject() throws IOException {
        assertEquals("sender", TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD.getSender());
        assertEquals("recipient", TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD.getRecipient());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    @Test
    public void shouldCreateXmlConformDraft() {
        String expectedXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "\n" +
                "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"list\"/>";

        String actualXml = SERIALIZER.serialize(TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD);
        assertEquals(expectedXml, actualXml);
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD);
        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
