package net.ripe.commons.provisioning.cms;

import static net.ripe.commons.certification.validation.ValidationString.CMS_DATA_PARSING;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import net.ripe.commons.certification.validation.ValidationResult;

import org.junit.Before;
import org.junit.Test;


public class ProvisioningCmsObjectParserTest {

    private ProvisioningCmsObjectParser subject;


    @Before
    public void setUp() {
        subject = new ProvisioningCmsObjectParser();
    }

    @Test
    public void shouldParseValidObject() {
        ProvisioningCmsObject cmsObject = ProvisioningCmsObjectBuilderMother.createProvisioningCmsObject();
        subject.parseCms("test-location", cmsObject.getEncoded());

        ValidationResult validationResult = subject.getValidationResult();
        assertFalse(validationResult.hasFailures());
        assertEquals(cmsObject, subject.getProvisioningCmsObject());
    }

    @Test(expected=ProvisioningCmsObjectParserException.class)
    public void shouldFailOnInvalidObject() {
        subject.parseCms("test-location", new byte[] {0});

        ValidationResult validationResult = subject.getValidationResult();
        assertTrue(validationResult.hasFailures());
        assertEquals(1, validationResult.getFailuresForCurrentLocation().size());
        assertEquals(CMS_DATA_PARSING, validationResult.getFailuresForCurrentLocation().iterator().next().getKey());

        subject.getProvisioningCmsObject(); // results in an exception
    }
}
