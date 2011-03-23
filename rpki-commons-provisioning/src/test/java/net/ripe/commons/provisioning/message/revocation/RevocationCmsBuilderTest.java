package net.ripe.commons.provisioning.message.revocation;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import org.junit.Test;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class RevocationCmsBuilderTest {
    @Test
    public void shouldBuildValidRevocationCms() throws Exception {
        // given
        RevocationCmsBuilder builder = new RevocationCmsBuilder();
        builder.withClassName("a classname");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender");
        builder.withRecipient("recipient");
        builder.withCertificate(ProvisioningObjectMother.X509_CA);

        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        RevocationPayloadWrapper revocationPayloadWrapper = (RevocationPayloadWrapper) parser.getPayloadWrapper();
        assertEquals("sender", revocationPayloadWrapper.getSender());
        assertEquals("recipient", revocationPayloadWrapper.getRecipient());

        RevocationPayload payloadContent = revocationPayloadWrapper.getPayloadContent();
        assertEquals("a classname", payloadContent.getClassName());
        assertArrayEquals(ProvisioningObjectMother.X509_CA.getSubjectKeyIdentifier(), payloadContent.getSubjectKeyIdentifier());
    }
}
