package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.util.Collections;
import java.util.List;

import net.ripe.commons.certification.validation.ValidationCheck;

import org.junit.Test;


public class NameValidatorTest {

    private static final List<String> EXISTING_NAMES = Collections.singletonList("MyRoa");

    private NameValidator subject = new NameValidator(EXISTING_NAMES);


    @Test
    public void shouldPassWithCorrectName() {
        ValidationResult result = subject.validate("Sample ROA");
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckIfNameIsNull() {
        ValidationResult result = subject.validate(null);

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_REQUIRED);
    }

    @Test
    public void shouldCheckIfNameIsBlank() {
        ValidationResult result = subject.validate(" ");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_REQUIRED);
    }

    @Test
    public void shouldCheckNamePattern() {
        ValidationResult result = subject.validate("$%");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_PATTERN);
    }

    @Test
    public void shouldCheckForDuplicates() {
        ValidationResult result = subject.validate(EXISTING_NAMES.get(0));

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_ALREADY_EXISTS);
    }

    @Test
    public void shouldSkipDuplicateCheckIfNameListNotSpecified() {
        subject = new NameValidator();
        ValidationResult result = subject.validate("My Roa");

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckNameLength() {
        StringBuilder sb = new StringBuilder();
        for(int i=0; i<2000; i++) {
            sb.append('x');
        }
        ValidationResult result = subject.validate(sb.toString());

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_LENGTH);
    }
}
