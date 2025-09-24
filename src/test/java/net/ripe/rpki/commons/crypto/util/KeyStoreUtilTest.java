package net.ripe.rpki.commons.crypto.util;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import static net.ripe.rpki.commons.crypto.util.KeyStoreUtil.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;

public class KeyStoreUtilTest {

    private static KeyPair TEST_KEY_PAIR = KeyPairFactory.rsa().generate();

    private KeyStore keyStore;

    private byte[] keyStoreData;

    public static final String DEFAULT_KEYSTORE_TYPE = "JKS";

    public static final String DEFAULT_KEYSTORE_PROVIDER = "SUN";


    @Test
    public void shouldKeyStoreContainExpiredCertificate() throws Exception {
        keyStore = createKeyStoreForKeyPair(TEST_KEY_PAIR, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER, DEFAULT_SIGNATURE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);
        keyStoreData = storeKeyStore(keyStore);

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(keyStore.getCertificateChain(KEYSTORE_KEY_ALIAS)[0].getEncoded()));
        assertTrue(certificate.getNotAfter().before(new Date()));
    }

    @Test
    public void shouldGetKeyPairFromKeyStore() {
        keyStore = createKeyStoreForKeyPair(TEST_KEY_PAIR, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER, DEFAULT_SIGNATURE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);
        keyStoreData = storeKeyStore(keyStore);

        KeyPair keyPair = getKeyPairFromKeyStore(keyStoreData, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);

        assertEquals(TEST_KEY_PAIR.getPrivate(), keyPair.getPrivate());
        assertEquals(TEST_KEY_PAIR.getPublic(), keyPair.getPublic());
    }

    @Test
    public void shouldClearKeyStore() throws GeneralSecurityException {
        keyStore = createKeyStoreForKeyPair(TEST_KEY_PAIR, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER, DEFAULT_SIGNATURE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);
        keyStoreData = storeKeyStore(keyStore);

        KeyStore emptyKeyStore = clearKeyStore(keyStoreData, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);

        assertFalse(emptyKeyStore.containsAlias(KEYSTORE_KEY_ALIAS));
    }

    @Test(expected = KeyStoreException.class)
    public void shouldCreateKeyStoreHandleError() throws GeneralSecurityException {
        // non existing provider
        createKeyStoreForKeyPair(TEST_KEY_PAIR, "foo keystore provider", DEFAULT_SIGNATURE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);
    }

    @Test(expected = KeyStoreException.class)
    public void shouldClearKeyStoreHandleError() throws GeneralSecurityException {
        // empty keystore data
        clearKeyStore(new byte[]{}, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);
    }

    @Test(expected = KeyStoreException.class)
    public void shouldStoreKeyStoreHandleError() throws GeneralSecurityException {
        // not initialized keystore
        storeKeyStore(KeyStore.getInstance(KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER));
    }
}
