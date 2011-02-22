package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.StringUtils;

public class PrefixValidator implements FieldValidator {

    private static final long serialVersionUID = 5663911278468240006L;

    private final IpResourceSet caResources;


    public PrefixValidator(IpResourceSet caResources) {
        this.caResources = caResources;
    }

    @Override
    public ValidationResult validate(String prefix) {
        ValidationResult result = new ValidationResult();
        if (!result.isFalse(StringUtils.isBlank(prefix), ROA_SPECIFICATION_PREFIX_REQUIRED)) {
            return result;
        }

        IpRange parsedPrefix = null;
        boolean validPrefix = true;
        try {
            parsedPrefix = IpRange.parse(prefix);
        } catch (IllegalArgumentException e) {
            validPrefix = false;
        }
        result.isTrue(validPrefix, ROA_SPECIFICATION_PREFIX_VALID, prefix);

        if (validPrefix) {
            result.isTrue(parsedPrefix.isLegalPrefix(), ROA_SPECIFICATION_PREFIX_VALID, prefix);
            result.isTrue(isResourceHeldByTheCurrentCA(parsedPrefix), ROA_SPECIFICATION_PREFIX_NOT_HELD_BY_CA, prefix);
        }

        return result;
    }

    private boolean isResourceHeldByTheCurrentCA(IpRange prefix) {
        IpResourceSet resourceSet = new IpResourceSet(prefix);
        resourceSet.removeAll(caResources);
        return resourceSet.isEmpty();
    }
}
