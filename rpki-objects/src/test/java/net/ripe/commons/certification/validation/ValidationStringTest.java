package net.ripe.commons.certification.validation;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.MissingResourceException;

import org.junit.Test;

public class ValidationStringTest {

    @Test
    public void shouldHaveMessageForEachField() throws Exception {
        Class<?> c = ValidationString.class;
        List<String> missingFields = new ArrayList<String>();
        for (Field f: c.getFields()) {
            String key = (String) f.get(null);
            ValidationCheck validationCheck = new ValidationCheck(true,key);
            try {
                ValidationMessage.getMessage(validationCheck);
            } catch (MissingResourceException e) {
                missingFields.add(key);
            }
        }
        if (missingFields.size() > 0) {
            org.junit.Assert.fail("Missing fields in BundleResource file (check ValidationMessage class for location): " + missingFields.toString());
        }
    }
}
