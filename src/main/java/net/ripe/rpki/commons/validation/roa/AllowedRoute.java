/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
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
package net.ripe.rpki.commons.validation.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.rpki.commons.crypto.cms.roa.Roa;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang.Validate;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;


/**
 * A route allowed by a ROA configuration.
 */
public class AllowedRoute extends EqualsSupport implements Serializable {
    private static final long serialVersionUID = 1L;

    private final Asn asn;
    private final IpRange prefix;
    private final int maximumLength;

    public AllowedRoute(Asn asn, IpRange prefix, int maximumLength) {
        Validate.notNull(asn, "asn is required");
        Validate.notNull(prefix, "prefix is required");
        Validate.isTrue(maximumLength >= 0 && maximumLength <= prefix.getType().getBitSize(), "maximumLength out of bounds");
        this.asn = asn;
        this.prefix = prefix;
        this.maximumLength = maximumLength;
    }

    public static List<AllowedRoute> fromRoas(List<? extends Roa> roas) {
        List<AllowedRoute> result = new ArrayList<AllowedRoute>();
        for (Roa roa : roas) {
            for (RoaPrefix roaPrefix : roa.getPrefixes()) {
                result.add(new AllowedRoute(roa.getAsn(), roaPrefix.getPrefix(), roaPrefix.getEffectiveMaximumLength()));
            }
        }
        return result;
    }

    public Asn getAsn() {
        return asn;
    }

    public IpRange getPrefix() {
        return prefix;
    }

    public int getMaximumLength() {
        return maximumLength;
    }

    public AnnouncedRoute getAnnouncedRoute() {
        return new AnnouncedRoute(asn, prefix);
    }

    public RoaPrefix getRoaPrefix() {
        Integer maxLen = prefix.getPrefixLength() == maximumLength ? null : maximumLength;
        return new RoaPrefix(prefix, maxLen);
    }
}
