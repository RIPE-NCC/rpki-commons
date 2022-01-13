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
package net.ripe.rpki.commons.provisioning.payload.issue.response;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.provisioning.payload.PayloadMessageType;
import net.ripe.rpki.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.rpki.commons.provisioning.payload.common.CertificateElement;
import net.ripe.rpki.commons.provisioning.payload.common.CertificateElementBuilder;
import net.ripe.rpki.commons.provisioning.payload.common.GenericClassElementBuilder;
import net.ripe.rpki.commons.xml.XmlSerializer;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class CertificateIssuanceResponsePayloadSerializerTest {
    private static final XmlSerializer<CertificateIssuanceResponsePayload> SERIALIZER = new CertificateIssuanceResponsePayloadSerializer();

    private static final Instant validityNotAfter = OffsetDateTime.of(2011, 1, 1, 23, 58, 23, 0, ZoneOffset.UTC).toInstant();

    public static final CertificateIssuanceResponsePayload TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD = createCertificateIssuanceResponsePayload();

    @Before
    public void given() {
        createCertificateIssuanceResponsePayload();
    }

    private static CertificateIssuanceResponsePayload createCertificateIssuanceResponsePayload() {
        CertificateElement certificateElement = new CertificateElementBuilder().withIpResources(IpResourceSet.parse("123,10.0.0.0/8,192.168.0.0/16,2001:0DB8::/48"))
                .withCertificatePublishedLocations(Arrays.asList(URI.create("rsync://jaja/jj,a"))).withCertificate(ProvisioningObjectMother.X509_CA).build();

        List<URI> certUris = new ArrayList<URI>();
        certUris.add(URI.create("rsync://localhost/so,me/where"));
        certUris.add(URI.create("http://some/other"));

        GenericClassElementBuilder classElementBuilder = new GenericClassElementBuilder().withClassName("a classname")
                .withCertificateAuthorityUri(certUris).withIpResourceSet(IpResourceSet.parse("1234,456,192.168.0.0/24,2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::"))
                .withValidityNotAfter(validityNotAfter).withSiaHeadUri("rsync://some/where").withCertificateElements(Arrays.asList(certificateElement))
                .withIssuer(ProvisioningObjectMother.X509_CA);

        CertificateIssuanceResponsePayloadBuilder builder = new CertificateIssuanceResponsePayloadBuilder();
        builder.withClassElement(classElementBuilder.buildCertificateIssuanceResponseClassElement());
        return builder.build();
    }

    @Test
    public void shouldBuildValidCIResponsePayload() throws URISyntaxException {
        assertEquals(PayloadMessageType.issue_response, TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD.getType());
    }

    // see: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.2
    @Test
    public void shouldHavePayloadXmlConformStandard() {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD);

        Pattern expectedXmlRegex = Pattern.compile("<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>\n"
                        + "<message\\s+xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\"\\s+recipient=\"recipient\"\\s+sender=\"sender\"\\s+type=\"issue_response\"\\s+version=\"1\">\n"
                        + "   <class\\s+cert_url=\"rsync://localhost/so%2Cme/where,http://some/other\"\\s+class_name=\"a classname\"\\s+resource_set_as=\"456,1234\"\\s+resource_set_ipv4=\"192.168.0.0/24\"\\s+resource_set_ipv6=\"2001:db8::/48,2001:db8:2::-2001:db8:5::\"\\s+resource_set_notafter=\"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\"\\s+suggested_sia_head=\"rsync://some/where\">\n"
                        + "      <certificate\\s+cert_url=\"rsync://jaja/jj%2Ca\"\\s+req_resource_set_as=\"123\"\\s+req_resource_set_ipv4=\"10.0.0.0/8,192.168.0.0/16\"\\s+req_resource_set_ipv6=\"2001:db8::/48\">[^<]*</certificate>\n"
                        + "      <issuer>[^<]*</issuer>\n"
                        + "   </class>\n"
                        + "</message>\n",
                Pattern.DOTALL
        );

        assertTrue("actual: " + actualXml, expectedXmlRegex.matcher(actualXml).matches());
    }

    @Test
    public void shouldDeserializeXml() {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD);
        CertificateIssuanceResponsePayload deserialized = SERIALIZER.deserialize(actualXml);
        // Deal with one-way comma encoding in URIs.
        assertEquals(TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD.toString(), deserialized.toString().replace("%2C", ","));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
