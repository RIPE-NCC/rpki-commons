package net.ripe.commons.provisioning.x509;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class ProvisioningIdentityCertificateBuilderTest {

    private ProvisioningIdentityCertificateBuilder subject;
    
    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSelfSigningKeyPair() {
        subject = new ProvisioningIdentityCertificateBuilder();
        subject.build(null, ProvisioningIdentityCertificateTest.SELF_SIGNING_DN);
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSelfSigningDN() {
        subject = new ProvisioningIdentityCertificateBuilder();
        subject.build(ProvisioningIdentityCertificateTest.TEST_KEY_PAIR, null);
    }
    
    @Test
    public void shouldBuild() {
        subject = new ProvisioningIdentityCertificateBuilder();
        ProvisioningIdentityCertificate identityCert = subject.build(ProvisioningIdentityCertificateTest.TEST_KEY_PAIR, ProvisioningIdentityCertificateTest.SELF_SIGNING_DN);
        assertNotNull(identityCert);
    }
    
}
