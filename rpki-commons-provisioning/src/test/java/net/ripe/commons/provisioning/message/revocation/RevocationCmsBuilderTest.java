package net.ripe.commons.provisioning.message.revocation;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
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
        builder.withRecipient("recipient");
        builder.withCertificate(ProvisioningObjectMother.X509_CA);
        builder.withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());


        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        RevocationPayloadWrapper revocationPayloadWrapper = (RevocationPayloadWrapper) parser.getPayloadWrapper();
        assertEquals("CN=test", revocationPayloadWrapper.getSender());
        assertEquals("recipient", revocationPayloadWrapper.getRecipient());

        RevocationPayload payloadContent = revocationPayloadWrapper.getPayloadContent();
        assertEquals("a classname", payloadContent.getClassName());
        assertArrayEquals(ProvisioningObjectMother.X509_CA.getSubjectKeyIdentifier(), payloadContent.getSubjectKeyIdentifier());
    }
}
