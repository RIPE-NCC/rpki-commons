package net.ripe.rpki.commons.provisioning.x509;


import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;

public class ProvisioningCmsCertificateParserTest {

    private ProvisioningCmsCertificateParser subject;


    @Before
    public void setUp() {
        subject = new ProvisioningCmsCertificateParser();
    }

    @Test
    public void shouldParseValidObject() {
        subject.parse("placeholder location", ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getEncoded());
        Assert.assertEquals(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT, subject.getCertificate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnInvalidObject() {
        subject.parse("placeholder location", new byte[]{0});

        ValidationResult validationResult = subject.getValidationResult();
        assertTrue(validationResult.hasFailures());
        assertEquals(1, validationResult.getFailuresForCurrentLocation().size());
        assertEquals(CERTIFICATE_PARSED, validationResult.getFailuresForCurrentLocation().iterator().next().getKey());

        subject.getCertificate(); // results in an exception
    }
}
