package net.ripe.commons.provisioning.payload.issue.request;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.regex.Pattern;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.payload.RelaxNgSchemaValidator;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

public class CertificateIssuanceRequestPayloadBuilderTest {

    private static final XStreamXmlSerializer<CertificateIssuanceRequestPayload> SERIALIZER = new CertificateIssuanceRequestPayloadSerializerBuilder().build();

    private PKCS10CertificationRequest pkcs10Request;
    private CertificateIssuanceRequestPayload payload;

    @Before
    public void given() throws Exception {
        pkcs10Request = ProvisioningObjectMother.RPKI_CA_CERT_REQUEST;
        payload = createCertificateIssuanceRequestPayloadForPkcs10Request(pkcs10Request);
    }

    public static CertificateIssuanceRequestPayload createCertificateIssuanceRequestPayloadForPkcs10Request(PKCS10CertificationRequest pkcs10Request) {
        CertificateIssuanceRequestPayloadBuilder builder = new CertificateIssuanceRequestPayloadBuilder();
        builder.withClassName("a classname");
        builder.withAllocatedAsn(IpResourceSet.parse("1234,456"));
        builder.withIpv4ResourceSet(IpResourceSet.parse("10.0.0.0/8"));
        builder.withIpv6ResourceSet(IpResourceSet.parse("2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::"));
        builder.withCertificateRequest(pkcs10Request);
        return builder.build();
    }
    
    @Test
    public void shouldBuildValidListResponsePayload() {
        assertEquals("sender", payload.getSender());
        assertEquals("recipient", payload.getRecipient());

        CertificateIssuanceRequestElement payloadContent = payload.getRequestElement();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals(IpResourceSet.parse("456,1234"), payloadContent.getAllocatedAsn());
        assertArrayEquals(pkcs10Request.getEncoded(), payloadContent.getCertificateRequest().getEncoded());
        assertEquals(IpResourceSet.parse("10.0.0.0/8"), payloadContent.getAllocatedIpv4());
        assertEquals(IpResourceSet.parse("2001:0DB8::/48,2001:0DB8:002::-2001:0DB8:005::"), payloadContent.getAllocatedIpv6());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.1
    @Test
    public void shouldUsePayloadXmlConformDraft() {
        
        String actualXml = SERIALIZER.serialize(payload);
        
        String expectedXmlRegex = "<\\?xml version=\"1.0\" encoding=\"UTF-8\"\\?>" + "\n" +
                                  "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"issue\">" + "\n" +
                                  "  <request class_name=\"a classname\" req_resource_set_as=\"456,1234\" req_resource_set_ipv4=\"10.0.0.0/8\" req_resource_set_ipv6=\"2001:db8::/48,2001:db8:2::-2001:db8:5::\">[^<]*</request>" + "\n" +
                                  "</message>";

        assertTrue(Pattern.matches(expectedXmlRegex, actualXml));
    }

    @Test
    public void shouldProduceSchemaValidatedXml() throws SAXException, IOException {
        String actualXml = SERIALIZER.serialize(payload);

        assertTrue(RelaxNgSchemaValidator.validateAgainstRelaxNg(actualXml));
    }
}
