/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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
package net.ripe.certification.client.xml.converters;

import static org.junit.Assert.*;

import net.ripe.commons.certification.util.VersionedId;

import org.junit.Test;


public class VersionedIdConverterTest {

    private VersionedIdConverter subject = new VersionedIdConverter();

    @Test
    public void shouldSupportVersionedId() {
        assertTrue(subject.canConvert(VersionedId.class));
    }

    @Test
    public void shouldParseVersionId() {
        assertEquals(new VersionedId(13, 0), subject.fromString("13"));
        assertEquals(new VersionedId(99, 0), subject.fromString("99:0"));
        assertEquals(new VersionedId(99, 13), subject.fromString("99:13"));
        assertEquals(new VersionedId(42), subject.fromString("42:-1"));
    }

    @Test
    public void shouldFormatVersionedId() {
        assertEquals("13:0", subject.toString(new VersionedId(13, 0)));
        assertEquals("42:-1", subject.toString(new VersionedId(42)));
        assertEquals("99:13", subject.toString(new VersionedId(99, 13)));
    }

}
