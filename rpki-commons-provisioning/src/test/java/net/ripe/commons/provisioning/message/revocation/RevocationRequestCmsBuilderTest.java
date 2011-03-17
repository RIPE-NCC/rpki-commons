package net.ripe.commons.provisioning.message.revocation;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import org.junit.Test;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertEquals;

public class RevocationRequestCmsBuilderTest {
    @Test
    public void shouldBuildValidRevocationCms() throws Exception {
        // given
        RevocationRequestCmsBuilder builder = new RevocationRequestCmsBuilder();
        builder.withClassName("a classname");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender");
        builder.withRecipient("recipient");
        builder.withSki("SKI");

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace with decoded from cms obj

        XStreamXmlSerializer<RevocationRequestPayloadWrapper> serializer = new RevocationRequestPayloadWrapperSerializerBuilder().build();
        RevocationRequestPayloadWrapper deserializedPayload = serializer.deserialize(builder.xml);

        System.out.println(builder.xml);

        assertEquals("sender", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());

        RevocationRequestPayload payloadContent = deserializedPayload.getPayloadContent();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals("SKI", payloadContent.getSki());
    }
}
