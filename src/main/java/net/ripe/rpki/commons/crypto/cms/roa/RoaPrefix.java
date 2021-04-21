/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.IpRange;
import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import javax.annotation.CheckForNull;
import java.io.Serializable;

public class RoaPrefix extends EqualsSupport implements Serializable {
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

    public Integer getMaximumLength() {
        return maximumLength;
    }

    public int getEffectiveMaximumLength() {
        return maximumLength != null ? maximumLength : getPrefix().getPrefixLength();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("prefix", getPrefix()).append("maximumLength", maximumLength).toString();
    }
}
