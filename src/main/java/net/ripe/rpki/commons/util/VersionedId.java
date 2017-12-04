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
package net.ripe.rpki.commons.util;

import org.apache.commons.lang.Validate;

import java.io.Serializable;
import java.util.StringTokenizer;

/**
 * A versioned identifier to uniquely identify a specific version of an entity.
 * This is used to implement optimistic locking.
 */
public class VersionedId implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final long INITIAL_VERSION = -1;

    private final long id;

    private final long version;

    /**
     * Creates a versioned identifier with the initial version. Used when first
     * creating an entity with a predefined id.
     */
    public VersionedId(long id) {
        this(id, INITIAL_VERSION);
    }

    public VersionedId(long id, long version) {
        this.id = id;
        this.version = version;
    }

    public long getId() {
        return id;
    }

    public long getVersion() {
        return version;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + (int) (version ^ (version >>> 32));
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final VersionedId other = (VersionedId) obj;
        if (id != other.id) {
            return false;
        }
        return version == other.version;
    }

    @Override
    public String toString() {
        return id + ":" + version;
    }

    public static VersionedId parse(String s) {
        Validate.notNull(s, "string required");
        StringTokenizer tokenizer = new StringTokenizer(s, ":");
        int count = tokenizer.countTokens();
        Validate.isTrue(count == 1 || count == 2, "invalid number of tokens in versioned id");
        long id = Long.parseLong(tokenizer.nextToken());
        long version;
        if (tokenizer.hasMoreTokens()) {
            version = Long.parseLong(tokenizer.nextToken());
        } else {
            version = 0;
        }
        return new VersionedId(id, version);
    }

}
