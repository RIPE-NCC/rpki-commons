package net.ripe.rpki.commons.validation;

import net.ripe.rpki.commons.util.EqualsSupport;

import java.io.Serializable;

public class ValidationCheck extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;

    private ValidationStatus status;
    private String key;
    private String[] params;

    public ValidationCheck(ValidationStatus status, String key, String... params) {
        this.status = status;
        this.key = key;
        this.params = params;
    }

    public String getKey() {
        return key;
    }

    public boolean isOk() {
        return status != ValidationStatus.ERROR;
    }

    public ValidationStatus getStatus() {
        return status;
    }

    public String[] getParams() {
        return params;
    }
}
