package net.ripe.commons.provisioning.cms;

import static net.ripe.commons.provisioning.x509.IdentityCertificateTest.*;

import org.junit.Before;
import org.junit.Test;

public class CmsObjectBuilderTest {

    private CmsObjectBuilder subject;


    @Before
    public void setUp() throws Exception {
        subject =  new CmsObjectBuilder();
    }

    @Test
    public void shouldBuildCmsObject() throws Exception {
        subject.withCertificate(TEST_SELF_SIGNED_X509_CERTIFICATE);
        subject.withSignatureProvider("SunRsaSign");
        subject.build(TEST_KEY_PAIR.getPrivate());
    }

}
