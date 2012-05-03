/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.validation;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Collections;

import net.ripe.commons.certification.FixedDateRule;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;


public class ValidationResultTest {

    private static final DateTime NOW = new DateTime(2008, 04, 05, 0, 0, 0, 0, DateTimeZone.UTC);

    @Rule
    public FixedDateRule fixedDateRule = new FixedDateRule(NOW);

    private ValidationResult result = new ValidationResult();

	@Test
	public void shouldValidateWithoutFailures() {
		final String validatedObject = "validatedObject";
		final ValidationLocation validatedObjectLocation = new ValidationLocation(validatedObject);

		result.setLocation(validatedObjectLocation);
		assertTrue(result.rejectIfFalse(true, "A"));
		assertTrue(result.rejectIfTrue(false, "B"));
		assertTrue(result.rejectIfNull("", "C"));

		assertFalse(result.hasFailures());
		assertFalse(result.hasFailureForLocation(validatedObjectLocation));
		assertFalse(result.hasFailureForLocation(new ValidationLocation("invalid object")));
		assertTrue(result.getValidatedLocations().size() == 1);
		assertTrue(result.getValidatedLocations().contains(validatedObjectLocation));
		assertNotNull(result.getAllValidationChecksForLocation(validatedObjectLocation));
		assertEquals(3, result.getAllValidationChecksForLocation(validatedObjectLocation).size());
		assertNotNull(result.getFailures(validatedObjectLocation));
		assertTrue(result.getFailures(validatedObjectLocation).size() == 0);
	}

	@Test
	public void shouldValidateWithFailures() {
		final String firstValidatedObject = "firstValidatedObject";
		ValidationLocation firstValidatedObjectLocation = new ValidationLocation(firstValidatedObject);

		final String secondValidatedObject = "secondValidatedObject";
		ValidationLocation secondValidatedObjectLocation = new ValidationLocation(secondValidatedObject);

		result.setLocation(firstValidatedObjectLocation);
		assertTrue(result.rejectIfFalse(true, "A"));
		assertTrue(result.rejectIfTrue(false, "B"));

		result.setLocation(secondValidatedObjectLocation);
		assertFalse(result.rejectIfFalse(false, "A"));
		assertFalse(result.rejectIfTrue(true, "B"));

		result.setLocation(firstValidatedObjectLocation);
		assertTrue(result.rejectIfNull("", "C"));

		result.setLocation(secondValidatedObjectLocation);
		assertFalse(result.rejectIfNull(null, "C"));

		assertTrue(result.hasFailures());
		assertFalse(result.hasFailureForLocation(firstValidatedObjectLocation));
		assertTrue(result.hasFailureForLocation(secondValidatedObjectLocation));
		assertTrue(result.getValidatedLocations().size() == 2);
		assertTrue(result.getValidatedLocations().contains(firstValidatedObjectLocation));
		assertTrue(result.getValidatedLocations().contains(secondValidatedObjectLocation));
		assertNotNull(result.getAllValidationChecksForLocation(firstValidatedObjectLocation));
		assertTrue(result.getAllValidationChecksForLocation(firstValidatedObjectLocation).size() == 3);
		assertNotNull(result.getAllValidationChecksForLocation(secondValidatedObjectLocation));
		assertTrue(result.getAllValidationChecksForLocation(secondValidatedObjectLocation).size() == 3);
		assertNotNull(result.getFailures(firstValidatedObjectLocation));
		assertTrue(result.getFailures(firstValidatedObjectLocation).size() == 0);
		assertNotNull(result.getFailures(secondValidatedObjectLocation));
		assertTrue(result.getFailures(secondValidatedObjectLocation).size() == 3);
	}

    @Test
    public void shouldHaveNoMetricsInitially() {
        assertEquals(Collections.emptyList(), result.getMetrics());
    }

    @Test
    public void shouldTrackValidationMetrics() {
        result.addMetric("name", "value");

        assertEquals(Arrays.asList(new ValidationMetric("name", "value", NOW.getMillis())), result.getMetrics());
    }
}
