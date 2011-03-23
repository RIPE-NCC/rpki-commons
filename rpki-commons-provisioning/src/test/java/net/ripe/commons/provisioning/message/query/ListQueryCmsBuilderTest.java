package net.ripe.commons.provisioning.message.query;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import org.junit.Test;

import java.io.IOException;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertEquals;

public class ListQueryCmsBuilderTest {

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    @Test
    public void shouldCreateListQueryXml() throws IOException {
        // given
        ListQueryCmsBuilder builder = new ListQueryCmsBuilder();
        builder.withSender("sender");
        builder.withRecipient("recipient");

        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL).withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());

        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        assertEquals("sender", parser.getPayloadWrapper().getSender());
        assertEquals("recipient", parser.getPayloadWrapper().getRecipient());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutRecipient() throws IOException {
        ListQueryCmsBuilder payloadBuilder = new ListQueryCmsBuilder();
        payloadBuilder.withRecipient("recipient");
        payloadBuilder.build(EE_KEYPAIR.getPrivate());
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.2
    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWithoutSender() throws IOException {
        ListQueryCmsBuilder payloadBuilder = new ListQueryCmsBuilder();
        payloadBuilder.withSender("sender");
        payloadBuilder.build(EE_KEYPAIR.getPrivate());
    }
}
