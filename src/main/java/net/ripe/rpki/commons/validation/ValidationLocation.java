package net.ripe.rpki.commons.validation;


import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.io.Serializable;
import java.net.URI;


/**
 * The validation location key that is used to associate validation checks with
 * a specific object or step. Typically the URI is used as the key.
 */
public class ValidationLocation implements Serializable, Comparable<ValidationLocation> {

    private static final long serialVersionUID = 1L;

    private final String name;

    public ValidationLocation(String name) {
        Validate.notEmpty(name, "name is required");
        this.name = name;
    }

    public ValidationLocation(URI objectUri) {
        this(objectUri.toString());
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("name", name).toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        ValidationLocation that = (ValidationLocation) o;

        if (!name.equals(that.name)) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public int compareTo(ValidationLocation o) {
        return this.name.compareTo(o.name);
    }
}
