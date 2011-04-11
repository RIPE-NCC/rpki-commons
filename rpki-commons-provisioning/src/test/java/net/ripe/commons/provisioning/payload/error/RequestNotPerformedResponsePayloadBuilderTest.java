package net.ripe.commons.provisioning.payload.error;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.commons.provisioning.payload.error.NotPerformedError;
import net.ripe.commons.provisioning.payload.error.RequestNotPerformedResponsePayload;
import net.ripe.commons.provisioning.payload.error.RequestNotPerformedResponsePayloadBuilder;
import net.ripe.commons.provisioning.payload.error.RequestNotPerformedResponsePayloadSerializerBuilder;

import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class RequestNotPerformedResponsePayloadBuilderTest {
    
    private static final String TEST_ERROR_DESCRIPTION = "Something went wrong";

    private static final NotPerformedError TEST_ERROR = NotPerformedError.INTERNAL_SERVER_ERROR;
    
    private RequestNotPerformedResponsePayloadBuilder builder;

    @Before
    public void given() {
        builder = new RequestNotPerformedResponsePayloadBuilder();
        builder.withSender("sender");
        builder.withRecipient("recipient");
        builder.withError(TEST_ERROR);
        builder.withDescription(TEST_ERROR_DESCRIPTION);
    }
    
    @Test
    public void shouldBuildValidListResponsePayload() throws Exception {
        // when
        String xml = builder.build();

        // then
        XStreamXmlSerializer<RequestNotPerformedResponsePayload> deserializer = new RequestNotPerformedResponsePayloadSerializerBuilder().build();

        RequestNotPerformedResponsePayload deserializedPayload = deserializer.deserialize(xml);

        assertEquals("sender", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());

        assertEquals(TEST_ERROR, deserializedPayload.getStatus());
        assertEquals(TEST_ERROR_DESCRIPTION, deserializedPayload.getDescription());
    }
    
    @Test
    public void shouldProduceXmlConformDraft() {
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");
        
        String expectedXml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "\n" +
            "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"error_response\">" + "\n" +
            "  <status>" + TEST_ERROR.getErrorCode() + "</status>" + "\n" +
            "  <description xml:lang=\"en-US\">" + TEST_ERROR_DESCRIPTION + "</description>" + "\n" +
            "</message>";
        
        assertEquals(expectedXml, actualXml);
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}