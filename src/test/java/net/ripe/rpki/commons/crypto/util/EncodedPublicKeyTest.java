package net.ripe.rpki.commons.crypto.util;

import org.junit.Before;
import org.junit.Test;

import java.security.PublicKey;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;


public class EncodedPublicKeyTest {

    private static final PublicKey PUBLIC_KEY = KeyPairFactoryTest.TEST_KEY_PAIR.getPublic();

    public EncodedPublicKey subject;


    @Before
    public void setUp() {
        // Make sure we're using an appropriate test key
        assertEquals("RSA", PUBLIC_KEY.getAlgorithm());
        subject = new EncodedPublicKey(PUBLIC_KEY.getEncoded());
    }

    @Test
    public void shouldReturnEncodedPart() {
        assertArrayEquals(PUBLIC_KEY.getEncoded(), subject.getEncoded());
    }

    @Test
    public void shouldReturnFormat() {
        assertEquals(PUBLIC_KEY.getFormat(), subject.getFormat()); subject.getFormat();
    }

    @Test
    public void shouldReturnAlgorithm() {
        assertEquals(PUBLIC_KEY.getAlgorithm(), subject.getAlgorithm());
    }
}
