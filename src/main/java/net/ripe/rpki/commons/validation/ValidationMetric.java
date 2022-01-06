package net.ripe.rpki.commons.validation;

import net.ripe.rpki.commons.util.EqualsSupport;

import java.io.Serializable;

/**
 * Captures interesting statistics related to validation.
 */
public class ValidationMetric extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;
    private final String value;
    private final long measuredAt;

    public ValidationMetric(String name, String value, long measuredAt) {
        this.name = name;
        this.value = value;
        this.measuredAt = measuredAt;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public long getMeasuredAt() {
        return measuredAt;
    }
}
