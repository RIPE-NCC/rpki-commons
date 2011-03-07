package net.ripe.commons.certification.validation;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;


public final class ValidationMessage {

    private static final String MESSAGE_BUNDLE_NAME = "validation";
    private static final Locale DEFAULT_LOCALE = Locale.ENGLISH;

    private ValidationMessage() {
    }

    public static String getMessage(ValidationCheck validationCheck) {
        ResourceBundle messages = ResourceBundle.getBundle(MESSAGE_BUNDLE_NAME, DEFAULT_LOCALE);
        return MessageFormat.format(messages.getString(validationCheck.getKey()), validationCheck.getParams());
    }
}
