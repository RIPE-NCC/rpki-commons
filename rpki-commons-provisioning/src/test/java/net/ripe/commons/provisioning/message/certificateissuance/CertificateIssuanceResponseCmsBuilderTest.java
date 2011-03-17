package net.ripe.commons.provisioning.message.certificateissuance;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.message.common.ResourceClass;
import net.ripe.commons.provisioning.message.common.ResourceClassBuilder;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;

import java.net.URISyntaxException;
import java.util.List;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CertificateIssuanceResponseCmsBuilderTest {
    private DateTime validityNotAfter = new DateTime(2011, 1, 1, 23, 58, 23, 12).withZone(DateTimeZone.UTC);

    @Test
    public void shouldBuildValidCIResponsePayload() throws URISyntaxException {
        // given
        CertificateIssuanceResponseCmsBuilder builder = new CertificateIssuanceResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri("rsync://localhost/some/where", "http://some/other");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender");
        builder.withRecipient("recipient");
        builder.withAllocatedAsn("1234", "456");
        builder.withIpv4ResourceSet("192.168.0.0/24");
        builder.withIpv6ResourceSet("2001:0DB8::/48", "2001:0DB8:002::-2001:0DB8:005::");
        builder.withResourceSet(new ResourceClassBuilder()
                .withAllocatedAsn("123")
                .withAllocatedIpv4("10.0.0.0/8")
                .withAllocatedIpv6("2001:0DB8::/48")
                .withIssuerCertificatePublicationLocation("rsync://jaja/jja")
                .withCertificate(ProvisioningObjectMother.X509_CA)
                .build());
        builder.withIssuer(ProvisioningObjectMother.X509_CA);

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace builder.xml with decoded from cms obj

        System.out.println(builder.xml);

        XStreamXmlSerializer<CertificateIssuanceResponsePayloadWrapper> serializer = new CertificateIssuanceResponsePayloadWrapperSerializerBuilder().build();
        CertificateIssuanceResponsePayloadWrapper deserializedPayload = serializer.deserialize(builder.xml);

        assertEquals("sender", deserializedPayload.getSender());
        assertEquals("recipient", deserializedPayload.getRecipient());

        CertificateIssuanceResponsePayload payload = deserializedPayload.getPayloadClass();
        assertEquals("http://some/other", payload.getCertificateAuthorityUri()[1]);
        assertEquals("a classname", payload.getClassName());
        assertEquals("192.168.0.0/24", payload.getIpv4ResourceSet()[0]);
        assertEquals("2001:0DB8:002::-2001:0DB8:005::", payload.getIpv6ResourceSet()[1]);

        assertArrayEquals(ProvisioningObjectMother.
                X509_CA.getEncoded(), payload.getIssuer().getEncoded());

        List<ResourceClass> resourceClasses = payload.getResourceClasses();
        assertEquals(1, resourceClasses.size());
        ResourceClass resourceClass = resourceClasses.get(0);
        assertEquals("rsync://jaja/jja", resourceClass.getIssuerCertificatePublicationLocation()[0]);
        assertEquals("123", resourceClass.getAllocatedAsn()[0]);
        assertEquals("10.0.0.0/8", resourceClass.getAllocatedIpv4()[0]);
        assertEquals("2001:0DB8::/48", resourceClass.getAllocatedIpv6()[0]);
        assertArrayEquals(ProvisioningObjectMother.X509_CA.getEncoded(), resourceClass.getCertificate().getEncoded());
    }

}
