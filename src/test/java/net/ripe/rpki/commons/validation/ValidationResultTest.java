/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.validation;

import net.ripe.rpki.commons.FixedDateRule;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;


public class ValidationResultTest {

    private static final ValidationLocation SECOND_LOCATION = new ValidationLocation("secondValidatedObject");

    private static final ValidationLocation FIRST_LOCATION = new ValidationLocation("firstValidatedObject");

    private static final DateTime NOW = new DateTime(2008, 4, 5, 0, 0, 0, 0, DateTimeZone.UTC);

    @Rule
    public FixedDateRule fixedDateRule = new FixedDateRule(NOW);

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
        assertTrue(result.getValidatedLocations().size() == 1);
        assertTrue(result.getValidatedLocations().contains(FIRST_LOCATION));
        assertNotNull(result.getAllValidationChecksForLocation(FIRST_LOCATION));
        assertEquals(3, result.getAllValidationChecksForLocation(FIRST_LOCATION).size());
        assertNotNull(result.getFailures(FIRST_LOCATION));
        assertTrue(result.getFailures(FIRST_LOCATION).size() == 0);
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
        assertTrue(result.getValidatedLocations().size() == 2);
        assertTrue(result.getValidatedLocations().contains(FIRST_LOCATION));
        assertTrue(result.getValidatedLocations().contains(SECOND_LOCATION));
        assertNotNull(result.getAllValidationChecksForLocation(FIRST_LOCATION));
        assertTrue(result.getAllValidationChecksForLocation(FIRST_LOCATION).size() == 3);
        assertNotNull(result.getAllValidationChecksForLocation(SECOND_LOCATION));
        assertTrue(result.getAllValidationChecksForLocation(SECOND_LOCATION).size() == 3);
        assertNotNull(result.getFailures(FIRST_LOCATION));
        assertTrue(result.getFailures(FIRST_LOCATION).size() == 0);
        assertNotNull(result.getFailures(SECOND_LOCATION));
        assertTrue(result.getFailures(SECOND_LOCATION).size() == 3);
    }

    @Test
    public void shouldHaveNoMetricsInitially() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        assertEquals(Collections.<ValidationMetric>emptyList(), result.getMetrics(FIRST_LOCATION));
    }

    @Test
    public void shouldTrackValidationMetrics() {
        result = ValidationResult.withLocation(FIRST_LOCATION);
        result.addMetric("name", "value");

        assertEquals(Arrays.asList(new ValidationMetric("name", "value", NOW.getMillis())), result.getMetrics(FIRST_LOCATION));
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
}
