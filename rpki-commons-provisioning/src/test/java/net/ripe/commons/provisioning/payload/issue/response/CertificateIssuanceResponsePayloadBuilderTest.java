package net.ripe.commons.provisioning.payload.issue.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.payload.PayloadMessageType;
import net.ripe.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.commons.provisioning.payload.common.CertificateElement;
import net.ripe.commons.provisioning.payload.common.CertificateElementBuilder;
import net.ripe.commons.provisioning.payload.common.GenericClassElementBuilder;
import net.ripe.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayload;
import net.ripe.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayloadBuilder;
import net.ripe.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayloadSerializerBuilder;
import net.ripe.ipresource.IpResourceSet;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class CertificateIssuanceResponsePayloadBuilderTest {
    private static final XStreamXmlSerializer<CertificateIssuanceResponsePayload> SERIALIZER = new CertificateIssuanceResponsePayloadSerializerBuilder().build();

    private DateTime validityNotAfter = new DateTime(2011, 1, 1, 23, 58, 23, 12).withZone(DateTimeZone.UTC);

    private CertificateIssuanceResponsePayloadBuilder builder;

    private CertificateIssuanceResponsePayload payload;

    @Before
    public void given() {

        // given
        CertificateElement certificateElement = new CertificateElementBuilder().withIpResources(IpResourceSet.parse("123,10.0.0.0/8,192.168.0.0/16,2001:0DB8::/48"))
                .withIssuerCertificatePublicationLocation(Arrays.asList(URI.create("rsync://jaja/jja"))).withCertificate(ProvisioningObjectMother.X509_CA).build();

        List<URI> certUris = new ArrayList<URI>();
        certUris.add(URI.create("rsync://localhost/some/where"));
        certUris.add(URI.create("http://some/other"));

        GenericClassElementBuilder classElementBuilder = new GenericClassElementBuilder().withClassName("a classname")
                .withCertificateAuthorityUri(certUris).withIpResourceSet(IpResourceSet.parse("1234,456,192.168.0.0/24,2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::"))
                .withValidityNotAfter(validityNotAfter).withSiaHeadUri("rsync://some/where").withCertificateElements(certificateElement)
                .withIssuer(ProvisioningObjectMother.X509_CA);

        builder = new CertificateIssuanceResponsePayloadBuilder();
        builder.withClassElement(classElementBuilder.buildCertificateIssuanceResponseClassElement());
        builder.withSender("sender");
        builder.withRecipient("recipient");
        payload = builder.build();
    }

    @Test
    public void shouldBuildValidCIResponsePayload() throws URISyntaxException {
        assertEquals(PayloadMessageType.issue_response, payload.getType());
    }

    // see: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2
    @Test
    public void shouldHavePayloadXmlConformStandard() {
        String actualXml = SERIALIZER.serialize(payload);

        String expectedXmlRegex = "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>"
                + "\n"
                + "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"issue_response\">"
                + "\n"
                + "  <class class_name=\"a classname\" cert_url=\"rsync://localhost/some/where,http://some/other\" resource_set_as=\"456,1234\" resource_set_ipv4=\"192.168.0.0/24\" resource_set_ipv6=\"2001:db8::/48,2001:db8:2::-2001:db8:5::\" resource_set_notafter=\"2011-01-01T22:58:23.012Z\" suggested_sia_head=\"rsync://some/where\">\n"
                + "    <certificate cert_url=\"rsync://jaja/jja\" req_resource_set_as=\"123\" req_resource_set_ipv4=\"10.0.0.0/8,192.168.0.0/16\" req_resource_set_ipv6=\"2001:db8::/48\">[^<]*</certificate>"
                + "\n" + "    <issuer>[^<]*</issuer>" + "\n" + "  </class>" + "\n" + "</message>";

        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(payload);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
