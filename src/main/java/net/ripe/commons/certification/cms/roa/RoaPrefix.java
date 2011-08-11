/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.commons.certification.cms.roa;

import java.io.Serializable;
import java.math.BigInteger;

import net.ripe.commons.certification.util.EqualsSupport;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceRange;
import net.ripe.ipresource.IpResourceType;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.hibernate.validator.AssertTrue;

public class RoaPrefix extends EqualsSupport implements Serializable {
    private static final long serialVersionUID = 1L;

    private BigInteger resourceStart;
    private BigInteger resourceEnd;
    private IpResourceType resourceType;
    private Integer maximumLength;

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
