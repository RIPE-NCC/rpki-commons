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
import org.apache.commons.lang.Validate;

import java.io.Serializable;
import java.util.Comparator;

/**
 * A route announced on BGP.
 */
public final class AnnouncedRoute implements Serializable {
    private static final long serialVersionUID = 1L;

    public static final Comparator<AnnouncedRoute> ASN_PREFIX_COMPARATOR = new Comparator<AnnouncedRoute>() {
        @Override
        public int compare(AnnouncedRoute o1, AnnouncedRoute o2) {
            int rc = o1.getOriginAsn().compareTo(o2.getOriginAsn());
            if (rc != 0) {
                return rc;
            }
            return o1.getPrefix().compareTo(o2.getPrefix());
        }
    };

    private final Asn originAsn;
    private final IpRange prefix;

    public AnnouncedRoute(Asn originAsn, IpRange prefix) {
        Validate.notNull(originAsn, "origin is required");
        Validate.isTrue(prefix.isLegalPrefix(), "Prefix must be legal");
        this.originAsn = originAsn;
        this.prefix = prefix;
    }

    public Asn getOriginAsn() {
        return originAsn;
    }

    public IpRange getPrefix() {
        return prefix;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + originAsn.hashCode();
        result = prime * result + prefix.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        AnnouncedRoute that = (AnnouncedRoute) obj;
        return this.originAsn.equals(that.originAsn) && this.prefix.equals(that.prefix);
    }

    @Override
    public String toString() {
        return "AnnouncedRoute [originAsn=" + originAsn + ", prefix=" + prefix + "]";
    }
}
