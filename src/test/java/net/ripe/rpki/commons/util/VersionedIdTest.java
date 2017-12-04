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

import org.junit.Test;

import static org.junit.Assert.*;


public class VersionedIdTest {

    @Test
    public void shouldDefaultToInitialVersion() {
        VersionedId subject = new VersionedId(9);
        assertEquals(9, subject.getId());
        assertEquals(VersionedId.INITIAL_VERSION, subject.getVersion());
    }

    @Test
    public void shouldHaveIdAndVersion() {
        VersionedId subject = new VersionedId(12, 32);
        assertEquals(12, subject.getId());
        assertEquals(32, subject.getVersion());
    }

    @Test
    public void testEquals() {
        assertEquals(new VersionedId(12, 32), new VersionedId(12, 32));
        assertEquals(new VersionedId(12, 32).hashCode(), new VersionedId(12, 32).hashCode());
        assertFalse(new VersionedId(12, 32).equals(new VersionedId(13, 32)));
        assertFalse(new VersionedId(12, 32).equals(new VersionedId(12, 33)));
    }

    @Test
    public void testToString() {
        assertEquals("12:32", new VersionedId(12, 32).toString());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailToParseEmptyString() {
        VersionedId.parse("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailToParseNullString() {
        VersionedId.parse(null);
    }

    @Test
    public void shouldParseIdWithVersion() {
        assertEquals(new VersionedId(3, 24), VersionedId.parse("3:24"));
    }

    @Test
    public void shouldParseWithoutVersion() {
        assertEquals(new VersionedId(3, 0), VersionedId.parse("3"));
    }

}
