package net.ripe.rpki.commons.crypto.cms.roa;

import lombok.ToString;
import net.ripe.ipresource.IpRange;
import org.apache.commons.lang3.Validate;

import javax.annotation.CheckForNull;
import java.io.Serializable;
import java.util.Comparator;
import java.util.Objects;

@ToString
public class RoaPrefix implements Serializable, Comparable<RoaPrefix> {
    private static final Comparator<RoaPrefix> ROA_PREFIX_COMPARATOR = Comparator.comparing(RoaPrefix::getPrefix)
            .thenComparing(RoaPrefix::getEffectiveMaximumLength, Comparator.nullsFirst(Comparator.naturalOrder()));
    private static final long serialVersionUID = 1L;

    private final IpRange prefix;
    @CheckForNull
    private final Integer maximumLength;

    public RoaPrefix(IpRange prefix) {
        this(prefix, null);
    }

    /**
     * Instantiate an RoaPrefix.
     *
     * @param prefix prefix of the ROA
     * @param maximumLength maximumLength of the ROA
     * @ensures that the maximumLength is valid compared to the prefix and for the address family of the prefix.
     */
    public RoaPrefix(IpRange prefix, Integer maximumLength) {
        Validate.notNull(prefix, "prefix is required");
        Validate.isTrue(prefix.isLegalPrefix(), "prefix is not a legal prefix");
        Validate.isTrue(maximumLength == null || (maximumLength >= prefix.getPrefixLength() && maximumLength <= prefix.getType().getBitSize()),
                "maximum length not in range");

        this.prefix = prefix;
        this.maximumLength = maximumLength;
    }

    public IpRange getPrefix() {
        return prefix;
    }

    /**
     * Return the maximum length as specified in the structure of the ROA.
     * <emph>Needed to exactly represent a decoded ROA.</emph> When consuming these objects, use {@link #getEffectiveMaximumLength()} where possible.
     */
    public Integer getMaximumLength() {
        return maximumLength;
    }

    public int getEffectiveMaximumLength() {
        return maximumLength != null ? maximumLength : getPrefix().getPrefixLength();
    }

    @Override
    public int compareTo(RoaPrefix o) {
        return ROA_PREFIX_COMPARATOR.compare(this, o);
    }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RoaPrefix roaPrefix = (RoaPrefix) o;
        return Objects.equals(prefix, roaPrefix.prefix) && Objects.equals(getEffectiveMaximumLength(), roaPrefix.getEffectiveMaximumLength());
    }

    @Override
    public int hashCode() {
        return Objects.hash(prefix, getEffectiveMaximumLength());
    }
}
