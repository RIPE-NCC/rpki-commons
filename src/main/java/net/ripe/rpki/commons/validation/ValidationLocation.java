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
public record ValidationLocation(String name) implements Serializable, Comparable<ValidationLocation> {

    private static final long serialVersionUID = 1L;

    public ValidationLocation {
        Validate.notEmpty(name, "name is required");
    }

    public ValidationLocation(URI objectUri) {
        this(objectUri.toString());
    }

    @Deprecated(forRemoval = true)
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("name", name).toString();
    }

    @Override
    public int compareTo(ValidationLocation o) {
        return this.name.compareTo(o.name);
    }
}
