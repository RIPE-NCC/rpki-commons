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
package net.ripe.rpki.commons.provisioning.payload.issue.request;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.rpki.commons.xml.XStreamXmlSerializer;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.junit.Assert.*;


public class CertificateIssuanceRequestPayloadBuilderTest {

    private static final XStreamXmlSerializer<CertificateIssuanceRequestPayload> SERIALIZER = new CertificateIssuanceRequestPayloadSerializerBuilder().build();

    public static final CertificateIssuanceRequestPayload TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD = createCertificateIssuanceRequestPayloadForPkcs10Request(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST);

    public static CertificateIssuanceRequestPayload createCertificateIssuanceRequestPayloadForPkcs10Request(PKCS10CertificationRequest pkcs10Request) {
        CertificateIssuanceRequestPayloadBuilder builder = new CertificateIssuanceRequestPayloadBuilder();
        builder.withClassName("ripe-region");
        builder.withAllocatedAsn(IpResourceSet.parse("1234,456"));
        builder.withIpv4ResourceSet(IpResourceSet.parse("10.0.0.0/8"));
        builder.withIpv6ResourceSet(IpResourceSet.parse("2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::"));
        builder.withCertificateRequest(pkcs10Request);
        return builder.build();
    }

    @Test
    public void shouldBuildValidListResponsePayload() throws IOException {
        assertEquals("sender", TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD.getSender());
        assertEquals("recipient", TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD.getRecipient());

        CertificateIssuanceRequestElement payloadContent = TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD.getRequestElement();
        assertEquals("ripe-region", payloadContent.getClassName());
        assertEquals(IpResourceSet.parse("456,1234"), payloadContent.getAllocatedAsn());
        PKCS10CertificationRequest pkcs10Request = ProvisioningObjectMother.RPKI_CA_CERT_REQUEST;
        assertArrayEquals(pkcs10Request.getEncoded(), payloadContent.getCertificateRequest().getEncoded());
        assertEquals(IpResourceSet.parse("10.0.0.0/8"), payloadContent.getAllocatedIpv4());
        assertEquals(IpResourceSet.parse("2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::"), payloadContent.getAllocatedIpv6());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1
    @Test
    public void shouldUsePayloadXmlConformDraft() {

        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD);

        String expectedXmlRegex = "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" + "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"issue\">" + "\n" + "  <request class_name=\"ripe-region\" req_resource_set_as=\"456,1234\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:db8::/48,2001:db8:2::-2001:db8:5::\">[^<]*</request>" + "\n" + "</message>";

        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
