package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class ListQueryCmsBuilderTest {
    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    @Test
    public void shouldCreateListQueryXml() throws IOException {
        ListQueryCmsBuilder builder = new ListQueryCmsBuilder().withSender("sender").withRecipient("recipient");

        builder.withCertificate(ProvisioningObjectMother.EE_CERT).withCrl(ProvisioningObjectMother.CRL);

        ProvisioningCmsObject cmsObject = builder.build(ProvisioningObjectMother.EE_KEYPAIR.getPrivate());

        String xml = builder.xml;

        assertEquals("<?xml version=\"1.0\" encoding=\"UTF-8\"?><message xmlns=\"http://www.apnic.net/specs/rescerts/up-down/\" version=\"1\" sender=\"sender\" recipient=\"recipient\" type=\"list\"/>", xml);
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutRecipient() throws IOException {
        ListQueryCmsBuilder payloadBuilder = new ListQueryCmsBuilder().withRecipient("recipient");
        payloadBuilder.build(ProvisioningObjectMother.EE_KEYPAIR.getPrivate());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutSender() throws IOException {
        ListQueryCmsBuilder payloadBuilder = new ListQueryCmsBuilder().withSender("sender");
        payloadBuilder.build(ProvisioningObjectMother.EE_KEYPAIR.getPrivate());
    }

}
