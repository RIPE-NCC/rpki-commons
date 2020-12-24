/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
package net.ripe.rpki.commons.provisioning.payload.list.request;

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
    public void shouldParseXml() {
        ResourceClassListQueryPayload payload = SERIALIZER.deserialize(XML);

        assertEquals(Integer.valueOf(1), payload.getVersion());
        assertEquals("sender attribute", payload.getSender());
        assertEquals("recipient attribute", payload.getRecipient());
        assertEquals(PayloadMessageType.list, payload.getType());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    @Test
    public void shouldCreateXmlConformDraft() {
        ResourceClassListQueryPayload payload = new ResourceClassListQueryPayload();
        payload.setSender("sender attribute");
        payload.setRecipient("recipient attribute");

        assertEquals(XML, SERIALIZER.serialize(payload));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD);
        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
