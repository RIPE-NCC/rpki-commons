package net.ripe.commons.certification;

import static org.junit.Assert.*;

import net.ripe.commons.certification.EncodedPublicKey;

import org.junit.Before;
import org.junit.Test;


public class EncodedPublicKeyTest {

    private static final byte[] ENCODED_PUBLIC_KEY = new byte[] {0};

    public EncodedPublicKey subject;


    @Before
    public void setUp() {
        subject = new EncodedPublicKey(ENCODED_PUBLIC_KEY);
    }

    @Test
    public void shouldReturnEncodedPart() {
        assertEquals(ENCODED_PUBLIC_KEY, subject.getEncoded());
    }

    @Test(expected=UnsupportedOperationException.class)
    public void shouldNotSpportFormat() {
        subject.getFormat();
    }

    @Test(expected=UnsupportedOperationException.class)
    public void shouldNotSpportAlgorithm() {
        subject.getAlgorithm();
    }
}
