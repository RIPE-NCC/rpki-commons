package net.ripe.commons.provisioning.cms;


import static net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilderTest.*;
import static org.junit.Assert.*;

import java.util.Set;

import net.ripe.commons.certification.validation.ValidationResult;

import org.junit.Before;
import org.junit.Test;

public class ProvisioningCmsObjectValidatorTest {

    private ProvisioningCmsObjectValidator subject;


    @Before
    public void setUp() throws Exception {
        subject = new ProvisioningCmsObjectValidator(createProvisioningCmsObject());
    }


    @Test
    public void shouldValidateValidObject() {
        ValidationResult validationResult = new ValidationResult();
        subject.validate(validationResult);

        assertFalse(validationResult.hasFailures());
    }

    @Test
    public void shouldHaveValidatedLocationsForAllObjects() {
        ValidationResult validationResult = new ValidationResult();
        subject.validate(validationResult);

        Set<String> validatedLocations = validationResult.getValidatedLocations();

        assertTrue(validatedLocations.contains("<cms>"));
        assertTrue(validatedLocations.contains("<crl>"));
        assertTrue(validatedLocations.contains("<cms-cert>"));
        assertTrue(validatedLocations.contains("<identity-cert>"));
    }
}
