package net.ripe.commons.provisioning.message.error;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;

import org.junit.Before;
import org.junit.Test;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertEquals;

public class RequestNotPerformedResponseCmsBuilderTest {
    
    private static final String TEST_ERROR_DESCRIPTION = "Something went wrong";

    private static final NotPerformedError TEST_ERROR = NotPerformedError.INTERNAL_SERVER_ERROR;
    
    private RequestNotPerformedResponseCmsBuilder builder;

    @Before
    public void given() {
        builder = new RequestNotPerformedResponseCmsBuilder();
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());
        builder.withRecipient("recipient");
        builder.withError(TEST_ERROR);
        builder.withDescription(TEST_ERROR_DESCRIPTION);
    }
    
    @Test
    public void shouldBuildValidListResponsePayload() throws Exception {
        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        RequestNotPerformedResponsePayload deserializedPayload = (RequestNotPerformedResponsePayload) parser.getPayloadWrapper();

        assertEquals("CN=test", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());

        assertEquals(TEST_ERROR, deserializedPayload.getStatus());
        assertEquals(TEST_ERROR_DESCRIPTION, deserializedPayload.getDescription());
    }
    
    @Test
    public void shouldProduceXmlConformDraft() {
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");
        
        String expectedXml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "\n" +
            "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"error_response\">" + "\n" +
            "  <status>" + TEST_ERROR.getErrorCode() + "</status>" + "\n" +
            "  <description xml:lang=\"en-US\">" + TEST_ERROR_DESCRIPTION + "</description>" + "\n" +
            "</message>";
        
        assertEquals(expectedXml, actualXml);
    }
    
}