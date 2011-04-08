package net.ripe.commons.provisioning.message.list.request;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.message.list.request.ResourceClassListQueryCmsBuilder;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import org.junit.Test;

import java.io.IOException;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertEquals;

public class ResourceClassListQueryCmsBuilderTest {

    @Test
    public void shouldCreateParsableProvisioningObject() throws IOException {
        // given
        ResourceClassListQueryCmsBuilder builder = new ResourceClassListQueryCmsBuilder();
        builder.withRecipient("recipient");

        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL).withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());

        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        assertEquals("CN=test", parser.getPayloadWrapper().getSender());
        assertEquals("recipient", parser.getPayloadWrapper().getRecipient());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    @Test
    public void shouldCreateXmlConformDraft() {
        ResourceClassListQueryCmsBuilder builder = new ResourceClassListQueryCmsBuilder();
        String expectedXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "\n" +
                             "<message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"list\"/>";
        
        String actualXml = builder.serializePayloadWrapper("sender", "recipient");
        assertEquals(expectedXml, actualXml);
    }
    
    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutRecipient() throws IOException {
        ResourceClassListQueryCmsBuilder payloadBuilder = new ResourceClassListQueryCmsBuilder();
        payloadBuilder.withRecipient("recipient");
        payloadBuilder.build(EE_KEYPAIR.getPrivate());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutSender() throws IOException {
        ResourceClassListQueryCmsBuilder payloadBuilder = new ResourceClassListQueryCmsBuilder();
        payloadBuilder.build(EE_KEYPAIR.getPrivate());
    }
}
