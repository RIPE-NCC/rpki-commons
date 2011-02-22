package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import net.ripe.ipresource.IpRange;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

public class MaximumLengthValidator implements FieldValidator {

    private static final long serialVersionUID = 2691080076021637679L;

    private final IpRange prefix;


    public MaximumLengthValidator(IpRange prefix) {
        Validate.notNull(prefix);
        this.prefix = prefix;
    }

    @Override
    public ValidationResult validate(String maxLength) {
        ValidationResult result = new ValidationResult();

        if (StringUtils.isBlank(maxLength)) {
            return result;
        }

        Integer maximumLength = null;
        boolean isMaxLengthValid = true;
        try {
            maximumLength = Integer.parseInt(maxLength);
        } catch (NumberFormatException e) {
            isMaxLengthValid = false;
        }
        result.isTrue(isMaxLengthValid, ROA_SPECIFICATION_MAX_LENGTH_VALID);

        if (isMaxLengthValid) {
            result.isTrue(isMaximumLengthValid(maximumLength), ROA_SPECIFICATION_MAX_LENGTH_VALID);
        }

        return result;
    }

    private boolean isMaximumLengthValid(Integer maximumLength) {
        return maximumLength == null || (maximumLength >= getMinimumValidLength() && maximumLength <= getMaximumValidLength());
    }

    private int getMaximumValidLength() {
        return prefix.getType().getBitSize() - 2;
    }

    private int getMinimumValidLength() {
        return prefix.getPrefixLength();
    }
}
