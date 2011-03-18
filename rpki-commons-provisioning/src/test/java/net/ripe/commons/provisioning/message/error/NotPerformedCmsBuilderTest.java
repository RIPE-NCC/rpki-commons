package net.ripe.commons.provisioning.message.error;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
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
        builder.withSender("sender");
        builder.withRecipient("recipient");
        builder.withError(NotPerformedError.INTERNAL_SERVER_ERROR);
        builder.withDescription("Something went wrong");

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace with decoded from cms obj

        XStreamXmlSerializer<NotPerformedPayloadWrapper> serializer = new NotPerformedPayloadSerializerBuilder().build();
        NotPerformedPayloadWrapper deserializedPayload = serializer.deserialize(builder.xml);

        System.out.println(builder.xml);

        assertEquals("sender", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());

        assertEquals(NotPerformedError.INTERNAL_SERVER_ERROR, deserializedPayload.getStatus());
        assertEquals("Something went wrong", deserializedPayload.getDescription());
    }
}
