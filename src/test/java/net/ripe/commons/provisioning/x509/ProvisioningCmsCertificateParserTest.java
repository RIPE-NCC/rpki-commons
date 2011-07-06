package net.ripe.commons.provisioning.x509;


import static net.ripe.commons.certification.validation.ValidationString.*;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.*;
import static org.junit.Assert.*;
import net.ripe.commons.certification.validation.ValidationResult;

import org.junit.Before;
import org.junit.Test;

public class ProvisioningCmsCertificateParserTest {

    private ProvisioningCmsCertificateParser subject;


    @Before
    public void setUp() {
        subject = new ProvisioningCmsCertificateParser();
    }

    @Test
    public void shouldParseValidObject() {
        subject.parse("placeholder location", TEST_CMS_CERT.getEncoded());
        assertEquals(TEST_CMS_CERT, subject.getCertificate());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldFailOnInvalidObject() {
        subject.parse("placeholder location", new byte[] {0});

        ValidationResult validationResult = subject.getValidationResult();
        assertTrue(validationResult.hasFailures());
        assertEquals(1, validationResult.getFailuresForCurrentLocation().size());
        assertEquals(CERTIFICATE_PARSED, validationResult.getFailuresForCurrentLocation().iterator().next().getKey());

        subject.getCertificate(); // results in an exception
    }
}
