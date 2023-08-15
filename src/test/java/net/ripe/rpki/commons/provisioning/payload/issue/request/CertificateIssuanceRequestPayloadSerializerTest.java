package net.ripe.rpki.commons.provisioning.payload.issue.request;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.rpki.commons.xml.XmlSerializer;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.util.regex.Pattern;

import static org.junit.Assert.*;


public class CertificateIssuanceRequestPayloadSerializerTest {

    private static final XmlSerializer<CertificateIssuanceRequestPayload> SERIALIZER = new CertificateIssuanceRequestPayloadSerializer();

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

        Pattern expectedXmlRegex = Pattern.compile("""
                <\\?xml version="1.0" encoding="UTF-8"\\?>
                <message\\s+xmlns="http://www.apnic.net/specs/rescerts/up-down/"\\s+recipient="recipient"\\s+sender="sender"\\s+type="issue"\\s+version="1">
                   <request\\s+class_name="ripe-region"\\s+req_resource_set_as="456,1234"\\s+req_resource_set_ipv4="10.0.0.0/8"\\s+req_resource_set_ipv6="2001:db8::/48,2001:db8:2::-2001:db8:5::">[^<]*</request>
                </message>
                """,
                Pattern.DOTALL);

        assertTrue("actual: " + actualXml, expectedXmlRegex.matcher(actualXml).matches());
    }

    @Test
    public void shouldDeserializeXml() {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD);
        CertificateIssuanceRequestPayload deserialized = SERIALIZER.deserialize(actualXml);
        assertEquals(TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD, deserialized);
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
