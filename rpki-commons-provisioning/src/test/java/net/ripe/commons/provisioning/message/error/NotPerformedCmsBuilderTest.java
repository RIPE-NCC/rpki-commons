package net.ripe.commons.provisioning.message.error;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import org.junit.Test;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertEquals;

public class NotPerformedCmsBuilderTest {
    @Test
    public void shouldBuildValidListResponsePayload() throws Exception {
        // given
        NotPerformedCmsBuilder builder = new NotPerformedCmsBuilder();
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withCaCertificate(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());
        builder.withRecipient("recipient");
        builder.withError(NotPerformedError.INTERNAL_SERVER_ERROR);
        builder.withDescription("Something went wrong");

        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        NotPerformedPayloadWrapper deserializedPayload = (NotPerformedPayloadWrapper) parser.getPayloadWrapper();

        assertEquals("CN=test", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());

        assertEquals(NotPerformedError.INTERNAL_SERVER_ERROR, deserializedPayload.getStatus());
        assertEquals("Something went wrong", deserializedPayload.getDescription());
    }
}
