package net.ripe.commons.certification.validation.fieldvalidators;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import net.ripe.commons.certification.validation.ValidationCheck;

import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

public class ValidationResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private Set<ValidationCheck> checkList =  new HashSet<ValidationCheck>();


    public boolean isTrue(boolean condition, String key, Object... param) {
        Validate.notNull(key, "key is required");
        checkList.add(new ValidationCheck(condition, key, param));
        return condition;
    }

    public boolean isFalse(boolean condition, String key, Object... param) {
        return isTrue(!condition, key, param);
    }

    public boolean notNull(Object object, String key, Object... param) {
        return isTrue(object != null, key, param);
    }

    public boolean hasFailures() {
        for (ValidationCheck vc : checkList) {
            if (!vc.isOk()) {
                return true;
            }
        }
        return false;
    }

    public List<ValidationCheck> getFailures() {
        List<ValidationCheck> failedList = new ArrayList<ValidationCheck>();
        for (ValidationCheck vc : checkList) {
            if (!vc.isOk()) {
                failedList.add(vc);
            }
        }
        return failedList;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
    }
}
