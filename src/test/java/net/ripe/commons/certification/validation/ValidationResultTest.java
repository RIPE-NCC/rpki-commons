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

import org.junit.Test;


public class ValidationResultTest {

	@Test
	public void shouldValidateWithoutFailures() {
		ValidationResult result = new ValidationResult();
		final String validatedObject = "validatedObject";

		result.push(validatedObject);
		assertTrue(result.isTrue(true, "A"));
		assertTrue(result.isFalse(false, "B"));
		assertTrue(result.notNull("", "C"));

		assertFalse(result.hasFailures());
		assertFalse(result.hasFailureForLocation(validatedObject));
		assertFalse(result.hasFailureForLocation("invalid object"));
		assertTrue(result.getValidatedLocations().size() == 1);
		assertTrue(result.getValidatedLocations().contains(validatedObject));
		assertNotNull(result.getResults(validatedObject));
		assertEquals(3, result.getResults(validatedObject).size());
		assertNotNull(result.getFailures(validatedObject));
		assertTrue(result.getFailures(validatedObject).size() == 0);
		assertNotNull(result.iterator(validatedObject));
	}

	@Test
	public void shouldValidateWithFailures() {
		ValidationResult result = new ValidationResult();
		final String firstValidatedObject = "firstValidatedObject";
		final String secondValidatedObject = "secondValidatedObject";

		result.push(firstValidatedObject);
		assertTrue(result.isTrue(true, "A"));
		assertTrue(result.isFalse(false, "B"));

		result.push(secondValidatedObject);
		assertFalse(result.isTrue(false, "A"));
		assertFalse(result.isFalse(true, "B"));

		result.push(firstValidatedObject);
		assertTrue(result.notNull("", "C"));

		result.push(secondValidatedObject);
		assertFalse(result.notNull(null, "C"));

		assertTrue(result.hasFailures());
		assertFalse(result.hasFailureForLocation(firstValidatedObject));
		assertTrue(result.hasFailureForLocation(secondValidatedObject));
		assertTrue(result.getValidatedLocations().size() == 2);
		assertTrue(result.getValidatedLocations().contains(firstValidatedObject));
		assertTrue(result.getValidatedLocations().contains(secondValidatedObject));
		assertNotNull(result.getResults(firstValidatedObject));
		assertTrue(result.getResults(firstValidatedObject).size() == 3);
		assertNotNull(result.getResults(secondValidatedObject));
		assertTrue(result.getResults(secondValidatedObject).size() == 3);
		assertNotNull(result.getFailures(firstValidatedObject));
		assertTrue(result.getFailures(firstValidatedObject).size() == 0);
		assertNotNull(result.getFailures(secondValidatedObject));
		assertTrue(result.getFailures(secondValidatedObject).size() == 3);
		assertNotNull(result.iterator(firstValidatedObject));
		assertNotNull(result.iterator(secondValidatedObject));
	}
}
