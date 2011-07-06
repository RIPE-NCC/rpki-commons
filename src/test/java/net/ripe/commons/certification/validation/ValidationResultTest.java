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
