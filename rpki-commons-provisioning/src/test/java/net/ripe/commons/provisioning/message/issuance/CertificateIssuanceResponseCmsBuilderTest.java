package net.ripe.commons.provisioning.message.issuance;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.common.ResourceClassBuilder;
import net.ripe.commons.provisioning.message.common.ResourceClassPayloadWrapper;
import net.ripe.commons.provisioning.message.common.ResourceClassPayloadWrapperSerializerBuilder;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;

import java.net.URISyntaxException;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
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
        builder.withValidityNotAfter(validityNotAfter);
        builder.withIssuer(ProvisioningObjectMother.X509_CA);

        // when
        builder.build(EE_KEYPAIR.getPrivate());

        // then
        // TODO replace builder.xml with decoded from cms obj

        System.out.println(builder.xml);

        XStreamXmlSerializer<ResourceClassPayloadWrapper> serializer = new ResourceClassPayloadWrapperSerializerBuilder().build();
        ResourceClassPayloadWrapper deserializedPayload = serializer.deserialize(builder.xml);

        assertEquals(PayloadMessageType.issue_response, deserializedPayload.getType());
    }

}
