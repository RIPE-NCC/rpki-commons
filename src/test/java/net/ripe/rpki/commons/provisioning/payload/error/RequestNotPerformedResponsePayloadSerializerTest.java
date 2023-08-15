package net.ripe.rpki.commons.provisioning.payload.error;

import net.ripe.rpki.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.rpki.commons.xml.XmlSerializer;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class RequestNotPerformedResponsePayloadSerializerTest {

    private static final String TEST_ERROR_DESCRIPTION = "Something went wrong";

    private static final NotPerformedError TEST_ERROR = NotPerformedError.INTERNAL_SERVER_ERROR;

    private static final XmlSerializer<RequestNotPerformedResponsePayload> SERIALIZER = new RequestNotPerformedResponsePayloadSerializer();

    public static final RequestNotPerformedResponsePayload NOT_PERFORMED_PAYLOAD = createRequestNotPerformedResponsePayload();

    public static RequestNotPerformedResponsePayload createRequestNotPerformedResponsePayload() {
        RequestNotPerformedResponsePayloadBuilder builder = new RequestNotPerformedResponsePayloadBuilder();
        builder.withError(TEST_ERROR);
        builder.withDescription(TEST_ERROR_DESCRIPTION);
        return builder.build();
    }

    @Test
    public void shouldBuildValidListResponsePayload() throws Exception {
        assertEquals("sender", NOT_PERFORMED_PAYLOAD.getSender());
        assertEquals("recipient", NOT_PERFORMED_PAYLOAD.getRecipient());

        assertEquals(TEST_ERROR, NOT_PERFORMED_PAYLOAD.getStatus());
        assertEquals(TEST_ERROR_DESCRIPTION, NOT_PERFORMED_PAYLOAD.getDescription());
    }

    @Test
    public void shouldProduceXmlConformDraft() {
        String actualXml = SERIALIZER.serialize(NOT_PERFORMED_PAYLOAD);

        Pattern expectedXml = Pattern.compile(
                "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>\n" +
                        "<message\\s+xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\"\\s+recipient=\"recipient\"\\s+sender=\"sender\"\\s+type=\"error_response\"\\s+version=\"1\">\n" +
                        "   <status>" + TEST_ERROR.getErrorCode() + "</status>\n" +
                        "   <description xml:lang=\"en-US\">" + TEST_ERROR_DESCRIPTION + "</description>\n" +
                        "</message>\n",
                Pattern.DOTALL
        );

        assertTrue("actual xml: " + actualXml, expectedXml.matcher(actualXml).matches());
    }

    @Test
    public void shouldDeserializeXml() {
        String actualXml = SERIALIZER.serialize(NOT_PERFORMED_PAYLOAD);
        RequestNotPerformedResponsePayload deserialized = SERIALIZER.deserialize(actualXml);
        assertEquals(NOT_PERFORMED_PAYLOAD, deserialized);
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(NOT_PERFORMED_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
