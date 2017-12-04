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
package net.ripe.rpki.commons.crypto.util;

import org.junit.Test;

import java.security.PublicKey;

import static org.junit.Assert.*;

public class KeyPairUtilTest {


    @Test
    public void testBase64UrlEncoding() {
        byte[] data = {
                (byte) 0xf9, 0x12, (byte) 0xff, (byte) 0x98, (byte) 0xa9, 0x34, 0x19
        };
        assertEquals("-RL_mKk0GQ==", KeyPairUtil.base64UrlEncode(data));
    }

    @Test
    public void testHexEncoding() {
        byte[] data = {
                (byte) 0xf9, 0x12, (byte) 0xff, (byte) 0x98, (byte) 0xa9, 0x34, 0x19
        };
        assertEquals("f912ff98a93419", KeyPairUtil.hexEncodeHashData(data));
    }

    @Test
    public void shouldStripPaddingFromEncodedKeyIdentifier() {
        // There is no need to decode the encoded key identifiers, so padding can be removed.
        PublicKey publicKey = KeyPairFactoryTest.TEST_KEY_PAIR.getPublic();
        String ski = KeyPairUtil.getEncodedKeyIdentifier(publicKey);
        assertTrue("encoded key identifier should not contain padding character", ski.indexOf('=') < 0);
        assertEquals(27, ski.length());
    }

}
