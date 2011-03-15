package net.ripe.commons.provisioning.message.resourceclassquery;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.*;
import static org.junit.Assert.*;

import java.io.IOException;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;

import org.junit.Test;

public class ListQueryCmsBuilderTest {

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    @Test
    public void shouldCreateListQueryXml() throws IOException {
        ListQueryCmsBuilder builder = new ListQueryCmsBuilder().withSender("sender").withRecipient("recipient");

        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL).withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());

        builder.build(EE_KEYPAIR.getPrivate());
        String xml = builder.xml;

        assertEquals("<?xml version=\"1.0\" encoding=\"UTF-8\"?><message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"list\"/>", xml);
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutRecipient() throws IOException {
        ListQueryCmsBuilder payloadBuilder = new ListQueryCmsBuilder().withRecipient("recipient");
        payloadBuilder.build(EE_KEYPAIR.getPrivate());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutSender() throws IOException {
        ListQueryCmsBuilder payloadBuilder = new ListQueryCmsBuilder().withSender("sender");
        payloadBuilder.build(EE_KEYPAIR.getPrivate());
    }
}
