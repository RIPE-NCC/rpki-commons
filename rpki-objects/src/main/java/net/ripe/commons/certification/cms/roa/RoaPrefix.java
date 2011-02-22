package net.ripe.commons.certification.cms.roa;

import java.math.BigInteger;

import javax.persistence.Column;
import javax.persistence.Embeddable;

import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceRange;
import net.ripe.ipresource.IpResourceType;
import net.ripe.utils.support.ValueObjectSupport;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.hibernate.validator.AssertTrue;
import org.hibernate.validator.NotNull;

@Embeddable
public class RoaPrefix extends ValueObjectSupport {

    private static final long serialVersionUID = 1L;

    @NotNull
    @Column(name = "resource_start", nullable = false)
    private BigInteger resourceStart;

    @NotNull
    @Column(name = "resource_end", nullable = false)
    private BigInteger resourceEnd;

    @NotNull
    @Column(name = "resource_type_id", nullable = false)
    private IpResourceType resourceType;

    @Column(name = "maximum_length", nullable = true)
    private Integer maximumLength;

    protected RoaPrefix() {

    }

    public RoaPrefix(IpRange prefix) {
        this(prefix, null);
    }
    
    public RoaPrefix(IpRange prefix, Integer maximumLength) {
        this.resourceType = prefix.getType();
        this.resourceStart = prefix.getStart().getValue();
        this.resourceEnd = prefix.getEnd().getValue();
        this.maximumLength = maximumLength;

    }

    public IpRange getPrefix() {
        return (IpRange) IpResourceRange.range(resourceType.fromBigInteger(resourceStart), resourceType.fromBigInteger(resourceEnd));
    }

    public Integer getMaximumLength() {
        return maximumLength;
    }

    @AssertTrue
    public boolean isMaximumLengthValid() {
        return maximumLength == null || (maximumLength >= getPrefix().getPrefixLength() && maximumLength <= getPrefix().getType().getBitSize());
    }

    @AssertTrue
    public boolean isValidPrefix() {
        return getPrefix().isLegalPrefix();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("prefix", getPrefix()).append("maximumLength", maximumLength).toString();
    }
}
