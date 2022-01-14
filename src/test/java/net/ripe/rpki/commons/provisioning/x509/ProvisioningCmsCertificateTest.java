package net.ripe.rpki.commons.provisioning.x509;

import org.junit.Test;

import static org.junit.Assert.*;

public class ProvisioningCmsCertificateTest {

    @Test(expected = NullPointerException.class)
    public void shouldCheckForNullArgument() {
        new ProvisioningCmsCertificate(null);
    }

    @Test
    public void shouldWrapX509Certificate() {
        assertNotNull(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate());
    }
}
