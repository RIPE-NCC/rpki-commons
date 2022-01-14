package net.ripe.rpki.commons.provisioning.x509;

import org.junit.Test;

import static org.junit.Assert.*;

public class ProvisioningIdentityCertificateTest {

    @Test(expected = NullPointerException.class)
    public void shouldCheckForNullArgument() {
        new ProvisioningIdentityCertificate(null);
    }

    @Test
    public void shouldWrapX509Certificate() {
        assertNotNull(ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getCertificate());
    }
}
