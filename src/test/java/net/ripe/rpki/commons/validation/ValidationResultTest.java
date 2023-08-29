package net.ripe.rpki.commons.validation;

import org.junit.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class ValidationResultTest {

    private static final ValidationLocation SECOND_LOCATION = new ValidationLocation("secondValidatedObject");

    private static final ValidationLocation FIRST_LOCATION = new ValidationLocation("firstValidatedObject");

    private static final Instant NOW = OffsetDateTime.of(2008, 4, 5, 0, 0, 0, 0, ZoneOffset.UTC).toInstant();

    private ValidationResult result;

    @Test
    public void shouldValidateWithoutFailures() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        assertTrue(result.rejectIfFalse(true, "A"));
        assertTrue(result.rejectIfTrue(false, "B"));
        assertTrue(result.rejectIfNull("", "C"));

        assertFalse(result.hasFailures());
        assertFalse(result.hasFailureForLocation(FIRST_LOCATION));
        assertFalse(result.hasFailureForLocation(new ValidationLocation("invalid object")));
        assertEquals(1, result.getValidatedLocations().size());
        assertTrue(result.getValidatedLocations().contains(FIRST_LOCATION));
        assertNotNull(result.getAllValidationChecksForLocation(FIRST_LOCATION));
        assertEquals(3, result.getAllValidationChecksForLocation(FIRST_LOCATION).size());
        assertNotNull(result.getFailures(FIRST_LOCATION));
        assertEquals(0, result.getFailures(FIRST_LOCATION).size());
    }

    @Test
    public void shouldValidateWithFailures() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        assertTrue(result.rejectIfFalse(true, "A"));
        assertTrue(result.rejectIfTrue(false, "B"));

        result.setLocation(SECOND_LOCATION);
        assertFalse(result.rejectIfFalse(false, "A"));
        assertFalse(result.rejectIfTrue(true, "B"));

        result.setLocation(FIRST_LOCATION);
        assertTrue(result.rejectIfNull("", "C"));

        result.setLocation(SECOND_LOCATION);
        assertFalse(result.rejectIfNull(null, "C"));

        assertTrue(result.hasFailures());
        assertFalse(result.hasFailureForLocation(FIRST_LOCATION));
        assertTrue(result.hasFailureForLocation(SECOND_LOCATION));
        assertEquals(2, result.getValidatedLocations().size());
        assertTrue(result.getValidatedLocations().contains(FIRST_LOCATION));
        assertTrue(result.getValidatedLocations().contains(SECOND_LOCATION));
        assertNotNull(result.getAllValidationChecksForLocation(FIRST_LOCATION));
        assertEquals(3, result.getAllValidationChecksForLocation(FIRST_LOCATION).size());
        assertNotNull(result.getAllValidationChecksForLocation(SECOND_LOCATION));
        assertEquals(3, result.getAllValidationChecksForLocation(SECOND_LOCATION).size());
        assertNotNull(result.getFailures(FIRST_LOCATION));
        assertEquals(0, result.getFailures(FIRST_LOCATION).size());
        assertNotNull(result.getFailures(SECOND_LOCATION));
        assertEquals(3, result.getFailures(SECOND_LOCATION).size());
    }

    @Test
    public void shouldHaveNoMetricsInitially() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        assertEquals(Collections.<ValidationMetric>emptyList(), result.getMetrics(FIRST_LOCATION));
    }

    @Test
    public void shouldTrackValidationMetrics() {
        result = ValidationResult.withLocation(FIRST_LOCATION).withClock(Clock.fixed(NOW, ZoneOffset.UTC));
        result.addMetric("name", "value");

        assertEquals(List.of(new ValidationMetric("name", "value", NOW.toEpochMilli())), result.getMetrics(FIRST_LOCATION));
        assertEquals(Collections.<ValidationMetric>emptyList(), result.getMetrics(SECOND_LOCATION));
    }

    @Test
    public void should_keep_checks_from_target_result() {
        ValidationResult source = ValidationResult.withLocation("n/a");
        result = ValidationResult.withLocation(FIRST_LOCATION);
        result.rejectForLocation(FIRST_LOCATION, "existing", "param");

        result.addAll(source);

        assertEquals(1, result.getFailures(FIRST_LOCATION).size());
        assertEquals("existing", result.getFailures(FIRST_LOCATION).get(0).getKey());
    }

    @Test
    public void should_copy_checks_from_source_result() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        ValidationResult source = ValidationResult.withLocation("n/a");
        source.rejectForLocation(FIRST_LOCATION, "added", "param");

        result.addAll(source);

        assertEquals(1, result.getFailures(FIRST_LOCATION).size());
        assertEquals("added", result.getFailures(FIRST_LOCATION).get(0).getKey());
    }

    @Test
    public void should_add_all_checks_from_both_results() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        ValidationResult source = ValidationResult.withLocation("n/a");
        source.rejectForLocation(FIRST_LOCATION, "added", "param");
        result.rejectForLocation(FIRST_LOCATION, "existing", "param");

        result.addAll(source);

        assertEquals(2, result.getFailures(FIRST_LOCATION).size());
        assertEquals("existing", result.getFailures(FIRST_LOCATION).get(0).getKey());
        assertEquals("added", result.getFailures(FIRST_LOCATION).get(1).getKey());
    }

    @Test
    public void should_track_if_there_are_any_warnings() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        result.error("an.error");
        result.setLocation(SECOND_LOCATION);
        assertFalse("no warnings yet", result.hasWarnings());

        result.warn("a.warning");
        assertTrue("warning correctly found", result.hasWarnings());
    }

    @Test
    public void should_track_if_there_are_any_errors() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        result.warn("a.warning");
        result.setLocation(SECOND_LOCATION);
        assertFalse("no failures yet", result.hasFailures());

        result.error("an.error");
        assertTrue("warning correctly found", result.hasFailures());
    }

    @Test
    public void should_not_store_passing_checks_when_requested() {
        result = ValidationResult.withLocation(FIRST_LOCATION).withoutStoringPassingChecks();
        result.pass("passed1");
        result.pass("passed2", "with", "params");
        result.rejectIfFalse(true, "passed3");
        result.warnIfNotNull(null, "passed4");
        assertEquals(0, result.getAllValidationChecksForCurrentLocation().size());
    }

    @Test
    public void should_still_store_warnings_when_not_storing_passing_checks() {
        result = ValidationResult.withLocation(FIRST_LOCATION).withoutStoringPassingChecks();
        result.warn("warning");
        assertEquals(1, result.getAllValidationChecksForCurrentLocation().size());
    }

    @Test
    public void should_still_store_errors_when_not_storing_passing_checks() {
        result = ValidationResult.withLocation(FIRST_LOCATION).withoutStoringPassingChecks();
        result.error("error");
        assertEquals(1, result.getAllValidationChecksForCurrentLocation().size());
    }

    @Test
    public void should_not_add_passed_checks_from_other_validation_result_when_not_storing_passing_checks() {
        result = ValidationResult.withLocation(FIRST_LOCATION).withoutStoringPassingChecks();
        ValidationResult that = ValidationResult.withLocation(SECOND_LOCATION);
        that.pass("passed");
        that.warn("warning");
        that.error("error");
        result.addAll(that);
        assertEquals(2, result.getAllValidationChecksForLocation(SECOND_LOCATION).size());
    }

    @Test
    public void should_remove_passed_checks_when_invoking_withoutPassingChecks() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        assertTrue(result.isStoringPassingChecks());
        result.pass("passed");
        assertEquals(1, result.getAllValidationChecksForCurrentLocation().size());
        result.withoutStoringPassingChecks();
        assertFalse(result.isStoringPassingChecks());
        assertEquals(0, result.getAllValidationChecksForCurrentLocation().size());
    }
}
