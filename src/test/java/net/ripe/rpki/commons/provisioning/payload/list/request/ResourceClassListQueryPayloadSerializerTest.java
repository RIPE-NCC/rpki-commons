package net.ripe.rpki.commons.provisioning.payload.list.request;

import net.ripe.rpki.commons.provisioning.identity.IdentitySerializerException;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.rpki.commons.xml.XmlSerializer;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;

import static org.junit.Assert.*;

public class ResourceClassListQueryPayloadSerializerTest {

    private static final XmlSerializer<ResourceClassListQueryPayload> SERIALIZER = new ResourceClassListQueryPayloadSerializer();
    public static final ResourceClassListQueryPayload TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD = new ResourceClassListQueryPayload();

    public static final String XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\"\n" +
            "         recipient=\"recipient attribute\"\n" +
            "         sender=\"sender attribute\"\n" +
            "         type=\"list\"\n" +
            "         version=\"1\"/>\n";

    @Test
    public void shouldCreateParsableProvisioningObject() throws IOException {
        assertEquals("sender", TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD.getSender());
        assertEquals("recipient", TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD.getRecipient());
    }

    @Test
    public void shouldParseXml() throws IdentitySerializerException {
        ResourceClassListQueryPayload payload = SERIALIZER.deserialize(XML);

        assertEquals(Integer.valueOf(1), payload.getVersion());
        assertEquals("sender attribute", payload.getSender());
        assertEquals("recipient attribute", payload.getRecipient());
        assertEquals(PayloadMessageType.list, payload.getType());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    @Test
    public void shouldCreateXmlConformDraft() throws IdentitySerializerException {
        ResourceClassListQueryPayload payload = new ResourceClassListQueryPayload();
        payload.setSender("sender attribute");
        payload.setRecipient("recipient attribute");

        assertEquals(XML, SERIALIZER.serialize(payload));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException, IdentitySerializerException {
        String actualXml = SERIALIZER.serialize(TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD);
        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
