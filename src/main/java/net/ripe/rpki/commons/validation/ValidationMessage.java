package net.ripe.rpki.commons.validation;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;


public final class ValidationMessage {

    private static final String MESSAGE_BUNDLE_NAME = "validation";
    private static final Locale DEFAULT_LOCALE = Locale.ENGLISH;

    private ValidationMessage() {
    }

    public static String getMessage(ValidationCheck validationCheck) {
        return getMessage(validationCheck, null);
    }

    public static String getMessage(ValidationCheck validationCheck, Locale locale) {
        ResourceBundle messages = null;
        if (locale != null) {
            try {
                messages = ResourceBundle.getBundle(MESSAGE_BUNDLE_NAME, locale);
            } catch (MissingResourceException e) {
            }
        }
        if (messages == null) {
            messages = ResourceBundle.getBundle(MESSAGE_BUNDLE_NAME, DEFAULT_LOCALE);
        }

        return MessageFormat.format(messages.getString(validationCheck.getKey() + "." + validationCheck.getStatus().getMessageKey()), (Object[]) validationCheck.getParams());
    }
}
