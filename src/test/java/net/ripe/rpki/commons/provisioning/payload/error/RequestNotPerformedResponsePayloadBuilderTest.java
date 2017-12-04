/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.provisioning.payload.error;

import net.ripe.rpki.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.rpki.commons.xml.XStreamXmlSerializer;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;

import static org.junit.Assert.*;

public class RequestNotPerformedResponsePayloadBuilderTest {

    private static final String TEST_ERROR_DESCRIPTION = "Something went wrong";

    private static final NotPerformedError TEST_ERROR = NotPerformedError.INTERNAL_SERVER_ERROR;

    private static final XStreamXmlSerializer<RequestNotPerformedResponsePayload> SERIALIZER = new RequestNotPerformedResponsePayloadSerializerBuilder().build();

    public static RequestNotPerformedResponsePayload NOT_PERFORMED_PAYLOAD = createRequestNotPerformedResponsePayload();

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
        String actualXml = SERIALIZER.serialize(NOT_PERFORMED_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}