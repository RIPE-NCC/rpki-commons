package net.ripe.commons.provisioning.message.certificateissuance;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.junit.Test;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CertificateIssuanceRequestCmsBuilderTest {
    @Test
    public void shouldBuildValidListResponsePayload() throws Exception {
        // given
        PKCS10CertificationRequest pkcs10Request = ProvisioningObjectMother.generatePkcs10CertificationRequest(512, "RSA", "SHA1withRSA", "BC");

        CertificateIssuanceRequestCmsBuilder builder = new CertificateIssuanceRequestCmsBuilder();
        builder.withClassName("a classname");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");
        builder.withAllocatedAsn("1234", "456");
        builder.withIpv4ResourceSet("10.0.0.0/8");
        builder.withIpv6ResourceSet("2001:0DB8::/48", "2001:0DB8:002::-2001:0DB8:005::");
        builder.withCertificateRequest(pkcs10Request);

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace with decoded from cms obj

        XStreamXmlSerializer<CertificateIssuanceRequestPayload> serializer = new CertificateIssuanceRequestPayloadSerializerBuilder().build();
        CertificateIssuanceRequestPayload deserializedPayload = serializer.deserialize(builder.xml);

        System.out.println(builder.xml);

        assertEquals("sender", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());

        CertificateIssuanceRequestContent payloadContent = deserializedPayload.getPayloadContent();
        assertEquals("a classname", payloadContent.getClassName());
        assertEquals("1234", payloadContent.getAllocatedAsn()[0]);
        assertArrayEquals(pkcs10Request.getEncoded(), payloadContent.getCertificate().getEncoded());
        assertEquals("10.0.0.0/8", payloadContent.getAllocatedIpv4()[0]);
        assertEquals("2001:0DB8:002::-2001:0DB8:005::", payloadContent.getAllocatedIpv6()[1]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutCertificate() throws Exception {
        // given
        CertificateIssuanceRequestCmsBuilder builder = new CertificateIssuanceRequestCmsBuilder();
        builder.withClassName("a classname");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");
        builder.withAllocatedAsn("1234", "456");

        // when
        builder.build(EE_KEYPAIR.getPrivate());
    }
}
