package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import net.ripe.ipresource.Asn;

import org.apache.commons.lang.StringUtils;

public class AsnValidator implements FieldValidator {

    private static final long serialVersionUID = 385212755144685126L;


    @Override
    public ValidationResult validate(String asn) {
        ValidationResult result = new ValidationResult();
        if (!result.isFalse(StringUtils.isBlank(asn), ROA_SPECIFICATION_ASN_REQUIRED)) {
            return result;
        }

        boolean validAsn = true;
        try {
            Asn.parse(asn);
        } catch (IllegalArgumentException e) {
            validAsn = false;
        }
        result.isTrue(validAsn, ROA_SPECIFICATION_ASN_VALID, asn);
        return result;
    }
}
