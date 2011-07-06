package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.util.List;

import net.ripe.commons.certification.validation.ValidationCheck;

import org.junit.Test;


public class DateTimeValidatorTest {

    private DateTimeValidator subject = new DateTimeValidator();


    @Test
    public void shouldPassWithCorrectDateTime() {
        ValidationResult result = subject.validate("2010-01-31 00:00");
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckIfDateTimeIsNull() {
        ValidationResult result = subject.validate(null);

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckIfNameIsBlank() {
        ValidationResult result = subject.validate(" ");

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldRejectIncorrectDateTimeFormat() {
        ValidationResult result = subject.validate("2010/12/31 00:59");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_DATE_TIME_VALID);
    }
}
