package net.ripe.commons.provisioning.message.resourceclassquery;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.*;

import java.net.URI;
import java.net.URISyntaxException;

import net.ripe.commons.provisioning.ProvisioningObjectMother;

import org.junit.Test;

public class ListResponseCmsBuilderTest {

    @Test
    public void shouldBuildValidListResponsePayload() throws URISyntaxException {

        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(new URI("rsync://localhost/some/where"));
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");

        builder.build(EE_KEYPAIR.getPrivate());

        // TODO remove
//        System.out.println(builder.xml);
    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutRsyncURI() throws URISyntaxException {
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(new URI("http://localhost/some/where"));
        builder.withCmsCertificate(TEST_CMS_CERT.getCertificate()).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");

        builder.build(EE_KEYPAIR.getPrivate());
    }
}