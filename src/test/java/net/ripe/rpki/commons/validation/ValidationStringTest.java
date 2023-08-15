package net.ripe.rpki.commons.validation;

import org.junit.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.MissingResourceException;

public class ValidationStringTest {

    @Test
    public void shouldHaveMessageForEachField() throws Exception {
        Class<?> c = ValidationString.class;
        List<String> missingFields = new ArrayList<>();
        for (Field f : c.getFields()) {
            String key = (String) f.get(null);
            ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, key);
            try {
                ValidationMessage.getMessage(validationCheck);
            } catch (MissingResourceException e) {
                missingFields.add(key);
            }
        }
        if (missingFields.size() > 0) {
            org.junit.Assert.fail("Missing fields in BundleResource file (check ValidationMessage class for location): " + missingFields);
        }
    }
}
