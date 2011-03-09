package net.ripe.commons.provisioning.x509;

import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;

import org.junit.Test;

public class ProvisioningIdentityCertificateTest {

    @SuppressWarnings("deprecation")
    @Test(expected=IllegalArgumentException.class)
    public void shouldCheckForNullArgument() {
        new ProvisioningIdentityCertificate(null);
    }

    @Test
    public void shouldWrapX509Certificate() {
        assertTrue(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate() instanceof X509Certificate);
    }

}
