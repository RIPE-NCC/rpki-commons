package net.ripe.rpki.commons.provisioning.cms;

import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;


public class ProvisioningCmsObjectParserTest {

    private ProvisioningCmsObjectParser subject;


    @Before
    public void setUp() {
        subject = new ProvisioningCmsObjectParser();
    }

    @Test
    public void shouldParseValidObject() {
        ProvisioningCmsObject cmsObject = ProvisioningObjectMother.createResourceClassListQueryProvisioningCmsObject();
        subject.parseCms("test-location", cmsObject.getEncoded());

        ValidationResult validationResult = subject.getValidationResult();
        assertFalse(validationResult.hasFailures());
        assertEquals(cmsObject, subject.getProvisioningCmsObject());
    }

    @Test(expected = ProvisioningCmsObjectParserException.class)
    public void shouldFailOnInvalidObject() {
        subject.parseCms("test-location", new byte[]{0});

        ValidationResult validationResult = subject.getValidationResult();
        assertTrue(validationResult.hasFailures());
        assertEquals(1, validationResult.getFailuresForCurrentLocation().size());
        assertEquals(CMS_DATA_PARSING, validationResult.getFailuresForCurrentLocation().iterator().next().getKey());

        subject.getProvisioningCmsObject(); // results in an exception
    }
}
