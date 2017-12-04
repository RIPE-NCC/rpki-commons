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
package net.ripe.rpki.commons.provisioning.payload.list.response;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.rpki.commons.provisioning.payload.common.CertificateElement;
import net.ripe.rpki.commons.provisioning.payload.common.CertificateElementBuilder;
import net.ripe.rpki.commons.provisioning.payload.common.GenericClassElementBuilder;
import net.ripe.rpki.commons.xml.XStreamXmlSerializer;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

public class ResourceClassListResponsePayloadBuilderTest {

    private static final XStreamXmlSerializer<ResourceClassListResponsePayload> SERIALIZER = new ResourceClassListResponsePayloadSerializerBuilder().build();


    private static DateTime validityNotAfter = new DateTime(2011, 1, 1, 23, 58, 23, 12).withZone(DateTimeZone.UTC);

    public static ResourceClassListResponsePayload TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD = createResourceClassListResponsePayload();


    public static ResourceClassListResponsePayload createResourceClassListResponsePayload() {
        ResourceClassListResponsePayloadBuilder builder = new ResourceClassListResponsePayloadBuilder();
        CertificateElement certificateElement = new CertificateElementBuilder().withIpResources(IpResourceSet.parse("123,10.0.0.0/8,2001:0DB8::/48"))
                .withCertificatePublishedLocations(Arrays.asList(URI.create("rsync://jaja/jja")))
                .withCertificate(ProvisioningObjectMother.X509_CA).build();

        GenericClassElementBuilder classElementBuilder = new GenericClassElementBuilder()
                .withClassName("a classname")
                .withCertificateAuthorityUri(Arrays.asList(URI.create("rsync://localhost/some/where"), URI.create("http://some/other")))
                .withIpResourceSet(IpResourceSet.parse("1234,456,192.168.0.0/24,2001:db8::/48,2001:0DB8:002::-2001:0DB8:005::"))
                .withValidityNotAfter(validityNotAfter)
                .withSiaHeadUri("rsync://some/where")
                .withCertificateElements(Arrays.asList(certificateElement))
                .withIssuer(ProvisioningObjectMother.X509_CA);

        builder.addClassElement(classElementBuilder.buildResourceClassListResponseClassElement());

        classElementBuilder.withClassName("class2");
        classElementBuilder.withCertificateElements(Arrays.asList(certificateElement, certificateElement));
        builder.addClassElement(classElementBuilder.buildResourceClassListResponseClassElement());

        return builder.build();
    }

    @Test
    public void shouldBuildValidListResponsePayload() throws URISyntaxException {
        assertEquals("sender", TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD.getSender());
        assertEquals("recipient", TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD.getRecipient());

        ResourceClassListResponseClassElement firstClassElement = TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD.getClassElements().get(0);
        assertEquals(URI.create("http://some/other"), firstClassElement.getCertificateAuthorityUri().get(1));
        assertEquals("a classname", firstClassElement.getClassName());
        assertEquals(IpResourceSet.parse("192.168.0.0/24"), firstClassElement.getResourceSetIpv4());


        assertEquals(IpResourceSet.parse("2001:db8::/48,2001:0DB8:002::-2001:0DB8:005::"), firstClassElement.getResourceSetIpv6());

        assertEquals(validityNotAfter, firstClassElement.getValidityNotAfter());
        assertEquals("rsync://some/where", firstClassElement.getSiaHeadUri());

        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), firstClassElement.getIssuer().getEncoded());

        List<CertificateElement> certificateElements = firstClassElement.getCertificateElements();
        assertEquals(1, certificateElements.size());
        CertificateElement certificateElement = certificateElements.get(0);
        assertEquals(URI.create("rsync://jaja/jja"), certificateElement.getIssuerCertificatePublicationUris().get(0));
        assertEquals(IpResourceSet.parse("123"), certificateElement.getAllocatedAsn());
        assertEquals(IpResourceSet.parse("10.0.0.0/8"), certificateElement.getAllocatedIpv4());
        assertEquals(IpResourceSet.parse("2001:0DB8::/48"), certificateElement.getAllocatedIpv6());
        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), certificateElement.getCertificate().getEncoded());
    }


    // see: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2
    @Test
    public void shouldCreatePayloadXmlConformDraft() {
        String actualXml = SERIALIZER.serialize(TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD);

        String expectedXmlRegex = "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" +
                "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"list_response\">" + "\n" +
                "  <class class_name=\"a classname\" cert_url=\"rsync://localhost/some/where,http://some/other\" resource_set_as=\"456,1234\" resource_set_ipv4=\"192.168.0.0/24\" resource_set_ipv6=\"2001:db8::/48,2001:db8:2::-2001:db8:5::\" resource_set_notafter=\"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\" suggested_sia_head=\"rsync://some/where\">\n" +
                "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:db8::/48\">[^<]*</certificate>" + "\n" +
                "    <issuer>[^<]*</issuer>" + "\n" +
                "  </class>" + "\n" +
                "  <class class_name=\"class2\" cert_url=\"rsync://localhost/some/where,http://some/other\" resource_set_as=\"456,1234\" resource_set_ipv4=\"192.168.0.0/24\" resource_set_ipv6=\"2001:db8::/48,2001:db8:2::-2001:db8:5::\" resource_set_notafter=\"\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z\" suggested_sia_head=\"rsync://some/where\">\n" +
                "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:db8::/48\">[^<]*</certificate>" + "\n" +
                "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:db8::/48\">[^<]*</certificate>" + "\n" +
                "    <issuer>[^<]*</issuer>" + "\n" +
                "  </class>" + "\n" +
                "</message>";

        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD);
        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
