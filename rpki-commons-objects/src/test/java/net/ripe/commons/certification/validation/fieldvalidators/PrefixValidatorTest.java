package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.util.List;

import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.ipresource.IpResourceSet;

import org.junit.Test;


public class PrefixValidatorTest {

    private static final IpResourceSet CA_RESOURCES = IpResourceSet.parse("10/8");

    private PrefixValidator subject = new PrefixValidator(CA_RESOURCES);


    @Test
    public void shouldPassWithCorrectPrefix() {
        ValidationResult result = subject.validate("10/16");
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckIfPrefixIsNull() {
        ValidationResult result = subject.validate(null);

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_PREFIX_REQUIRED);
    }

    @Test
    public void shouldCheckIfPrefixIsBlank() {
        ValidationResult result = subject.validate(" ");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_PREFIX_REQUIRED);
    }

    @Test
    public void shouldCheckIfPrefixIsValid() {
        ValidationResult result = subject.validate("10/foo");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_PREFIX_VALID);
    }

    @Test
    public void shouldCheckIfPrefixIsLegal() {
        ValidationResult result = subject.validate("10/0");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_PREFIX_VALID);
    }

    @Test
    public void shouldCheckIfResourceIsHeldByCa() {
        ValidationResult result = subject.validate("192.168/16");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_PREFIX_NOT_HELD_BY_CA);
    }
}
