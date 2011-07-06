package net.ripe.commons.provisioning.x509;

import static org.junit.Assert.*;

import java.security.cert.X509Certificate;

import org.junit.Test;

public class ProvisioningCmsCertificateTest {

    @Test(expected=IllegalArgumentException.class)
    public void shouldCheckForNullArgument() {
        new ProvisioningCmsCertificate(null);
    }

    @Test
    public void shouldWrapX509Certificate() {
        assertTrue(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate() instanceof X509Certificate);
    }
}
