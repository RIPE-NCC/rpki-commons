package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;

import org.apache.commons.lang.StringUtils;

public class DateTimeValidator implements FieldValidator {

    private static final long serialVersionUID = -1653745178216658970L;


    @Override
    public ValidationResult validate(String date) {
        ValidationResult result = new ValidationResult();

        // we allow empty dates
        if (StringUtils.isBlank(date)) {
            return result;
        }

        boolean validDateTime = true;

        try {
            UTCDateTimeFormatter.getInstance().parseDateTime(date);
        } catch (IllegalArgumentException e) {
            validDateTime = false;
        }
        result.isTrue(validDateTime, ROA_SPECIFICATION_DATE_TIME_VALID, date);
        return result;
    }
}
