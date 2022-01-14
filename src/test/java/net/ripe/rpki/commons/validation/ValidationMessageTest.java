package net.ripe.rpki.commons.validation;

import org.junit.Test;

import java.util.Locale;

import static org.junit.Assert.*;


public class ValidationMessageTest {

    @Test
    public void shouldResolveMessage() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck));
    }

    @Test
    public void shouldFormatMessageArguments() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.VALIDATOR_URI_HOST, "rsync://localhost/path/");
        assertEquals("URI 'rsync://localhost/path/' contains a host", ValidationMessage.getMessage(validationCheck));
    }

    @Test
    public void shouldUseSpecifiedLocale() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Het certificaat kon ingelezen worden", ValidationMessage.getMessage(validationCheck, Locale.forLanguageTag("test")));
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck, Locale.US));
    }

    @Test
    public void shouldFallbackToDefaultLocale() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck, Locale.FRENCH));
    }

    @Test
    public void shouldFallbackToLanguageFromFullLocale() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck, Locale.US));
    }
}
