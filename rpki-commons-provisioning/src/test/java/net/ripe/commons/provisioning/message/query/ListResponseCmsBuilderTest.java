package net.ripe.commons.provisioning.message.query;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.commons.provisioning.message.PayloadMessageType;
import net.ripe.commons.provisioning.message.common.ResourceClassBuilder;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;

import java.net.URISyntaxException;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static org.junit.Assert.assertEquals;

public class ListResponseCmsBuilderTest {

    private DateTime validityNotAfter = new DateTime(2011, 1, 1, 23, 58, 23, 12).withZone(DateTimeZone.UTC);

    @Test
    public void shouldBuildValidListResponsePayload() throws URISyntaxException {
        // given
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri("rsync://localhost/some/where", "http://some/other");
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender");
        builder.withRecipient("recipient");
        builder.withAllocatedAsn("1234", "456");
        builder.withIpv4ResourceSet("192.168.0.0/24");
        builder.withIpv6ResourceSet("2001:0DB8::/48", "2001:0DB8:002::-2001:0DB8:005::");
        builder.withValidityNotAfter(validityNotAfter);
        builder.withSiaHeadUri("rsync://some/where");
        builder.withResourceSet(new ResourceClassBuilder()
                .withAllocatedAsn("123")
                .withAllocatedIpv4("10.0.0.0/8")
                .withAllocatedIpv6("2001:0DB8::/48")
                .withIssuerCertificatePublicationLocation("rsync://jaja/jja")
                .withCertificate(ProvisioningObjectMother.X509_CA)
                .build());
        builder.withIssuer(ProvisioningObjectMother.X509_CA);

        // when
        ProvisioningCmsObject cmsObject = builder.build(EE_KEYPAIR.getPrivate());

        // then
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("/tmp/", cmsObject.getEncoded());

        assertEquals(PayloadMessageType.list_response, parser.getPayloadWrapper().getType());
    }
}