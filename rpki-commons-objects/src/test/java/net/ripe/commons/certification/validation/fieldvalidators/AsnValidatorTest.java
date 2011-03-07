package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.util.List;

import net.ripe.commons.certification.validation.ValidationCheck;

import org.junit.Test;


public class AsnValidatorTest {

    private AsnValidator subject = new AsnValidator();


    @Test
    public void shouldPassWithCorrectAsNumber() {
        ValidationResult result = subject.validate("AS123");
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckIfAsnIsNull() {
        ValidationResult result = subject.validate(null);

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_ASN_REQUIRED);
    }

    @Test
    public void shouldCheckIfAsnIsBlank() {
        ValidationResult result = subject.validate(" ");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_ASN_REQUIRED);
    }

    @Test
    public void shouldFailWithMalformedAsNumber() {
        ValidationResult result = subject.validate("12AS");
        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_ASN_VALID);
    }
}
