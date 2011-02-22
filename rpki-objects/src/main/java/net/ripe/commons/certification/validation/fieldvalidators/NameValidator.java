package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

public class NameValidator implements FieldValidator {

    private static final String NAME_PATTERN_STRING = "[A-Za-z0-9-_:@.+ <>]+";
    private static final Pattern NAME_PATTERN = Pattern.compile(NAME_PATTERN_STRING);
    private static final int MAX_NAME_LENGTH = 2000;
    private static final long serialVersionUID = -938017808691917812L;
    private final List<String> existingNames;


    public NameValidator() {
        this.existingNames = Collections.<String>emptyList();
    }

    public NameValidator(List<String> existingNames) {
        Validate.notNull(existingNames);
        this.existingNames = existingNames;
    }

    @Override
    public ValidationResult validate(String name) {
        ValidationResult result = new ValidationResult();
        if (!result.isFalse(StringUtils.isBlank(name), ROA_SPECIFICATION_NAME_REQUIRED)) {
            return result;
        }
        result.isTrue(NAME_PATTERN.matcher(name).matches(), ROA_SPECIFICATION_NAME_PATTERN);
        result.isTrue(name.length() < MAX_NAME_LENGTH, ROA_SPECIFICATION_NAME_LENGTH, MAX_NAME_LENGTH);
        result.isFalse(existingNames.contains(name), ROA_SPECIFICATION_NAME_ALREADY_EXISTS);
        return result;
    }
}
