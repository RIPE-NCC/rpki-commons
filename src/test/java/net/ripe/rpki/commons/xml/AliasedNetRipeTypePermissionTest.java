/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
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
package net.ripe.rpki.commons.xml;

import com.thoughtworks.xstream.XStream;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;

public class AliasedNetRipeTypePermissionTest {
    private XStream xStream;
    private AliasedNetRipeTypePermission permission;

    @Before
    public void initialize() {
        this.xStream = new XStream();
        this.permission = new AliasedNetRipeTypePermission(xStream);
    }

    /**
     * Initially rejected but accepted after being aliased.
     */
    @Test
    public void shouldAcceptAliasedTypes() {
        Assert.assertFalse(this.permission.allows(SerializeMe.class));

        xStream.alias("serialize-me", SerializeMe.class);

        Assert.assertTrue(this.permission.allows(SerializeMe.class));
    }

    @Test
    public void shouldAcceptAliasedPackageMembers() {
        Assert.assertFalse(this.permission.allows(SerializeMe.class));

        xStream.aliasPackage("rpki-commons", "net.ripe.rpki.commons");

        Assert.assertTrue(this.permission.allows(SerializeMe.class));
    }

    /**
     * Reject a non-ripe type. If a non-ripe type needs to be accepted because of an default alias exists for it,
     * it should be allowed explicitly.
     */
    @Test
    public void shoudldRejectNonRipeTypes() {
        xStream.alias("non-ripe-type", ArrayList.class);

        Assert.assertFalse(this.permission.allows(ArrayList.class));
    }

    private static class SerializeMe {
    }
}
