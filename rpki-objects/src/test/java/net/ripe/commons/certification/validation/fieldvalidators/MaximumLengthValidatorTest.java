package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.util.List;

import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.ipresource.IpRange;

import org.junit.Test;


public class MaximumLengthValidatorTest {

    private static final IpRange PREFIX = IpRange.parse("10/8");

    private MaximumLengthValidator subject = new MaximumLengthValidator(PREFIX);


    @Test
    public void shouldPassWithCorrectLength() {
        ValidationResult result = subject.validate("16");
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldPassWithoutMaxLengthSpecified() {
        ValidationResult result = subject.validate(null);
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldPassIfMaxLegthIsBlank() {
        ValidationResult result = subject.validate(" ");
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckIfMaxLengthIsValid() {
        ValidationResult result = subject.validate("foo");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_MAX_LENGTH_VALID);
    }

    @Test
    public void shouldCheckIfMaxLengthIsLegal() {
        ValidationResult result = subject.validate("7");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_MAX_LENGTH_VALID);
    }

    @Test
    public void shouldCheckIfMaxLengthIsNotMoreSpecificThanBitsizeMinusTwo() {
        ValidationResult result = subject.validate("31");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_MAX_LENGTH_VALID);
    }
}
