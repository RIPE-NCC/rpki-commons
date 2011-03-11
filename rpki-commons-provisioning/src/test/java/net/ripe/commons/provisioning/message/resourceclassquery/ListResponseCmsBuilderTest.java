package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;

public class ListResponseCmsBuilderTest {

    @Test
    public void shouldBuildValidListResponsePayload() throws URISyntaxException {

        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(new URI("rsync://localhost/some/where"));
        builder.withCertificate(ProvisioningObjectMother.EE_CERT).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");

        builder.build(ProvisioningObjectMother.EE_KEYPAIR.getPrivate());

        // TODO remove
//        System.out.println(builder.xml);


    }

    // http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3
    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutRsyncURI() throws URISyntaxException {
        ListResponseCmsBuilder builder = new ListResponseCmsBuilder();
        builder.withClassName("a classname");
        builder.withCertificateAuthorityUri(new URI("http://localhost/some/where"));
        builder.withCertificate(ProvisioningObjectMother.EE_CERT).withCrl(ProvisioningObjectMother.CRL);
        builder.withSender("sender").withRecipient("recipient");

        builder.build(ProvisioningObjectMother.EE_KEYPAIR.getPrivate());
    }
}