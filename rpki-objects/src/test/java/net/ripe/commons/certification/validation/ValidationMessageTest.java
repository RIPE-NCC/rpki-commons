package net.ripe.commons.certification.validation;

import static org.junit.Assert.*;

import java.net.URI;

import org.junit.Test;


public class ValidationMessageTest {

    @Test
    public void shouldResolveMessage() {
        ValidationCheck validationCheck = new ValidationCheck(true, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck));
    }

    @Test
    public void shouldFormatMessageArguments() {
        ValidationCheck validationCheck = new ValidationCheck(true, ValidationString.VALIDATOR_URI_HOST, URI.create("rsync://localhost/path/"));
        assertEquals("URI 'rsync://localhost/path/' contains a host", ValidationMessage.getMessage(validationCheck));
    }
}
