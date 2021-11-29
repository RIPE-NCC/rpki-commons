/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
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
package net.ripe.rpki.commons.provisioning.payload.revocation.response;

import net.ripe.rpki.commons.crypto.util.KeyPairUtil;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
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
    public void shouldProduceXmlConformStandard() {
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
    public void shouldDeserializeXml() {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD);
        CertificateRevocationResponsePayload deserialized = SERIALIZER.deserialize(actualXml);
        assertEquals(TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD, deserialized);
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
