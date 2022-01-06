package net.ripe.rpki.commons.validation;

public enum ValidationStatus {
    ERROR, WARNING, PASSED, FETCH_ERROR;

    public String getMessageKey() {
        return (this == FETCH_ERROR ? ERROR : this).name().toLowerCase();
    }
}
