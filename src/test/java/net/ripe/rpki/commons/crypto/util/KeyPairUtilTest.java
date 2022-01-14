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
