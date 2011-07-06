package net.ripe.commons.certification.util;

import static net.ripe.commons.certification.util.KeyPairFactoryTest.DEFAULT_KEYPAIR_GENERATOR_PROVIDER;
import static net.ripe.commons.certification.util.KeyStoreUtil.KEYSTORE_KEY_ALIAS;
import static net.ripe.commons.certification.util.KeyStoreUtil.clearKeyStore;
import static net.ripe.commons.certification.util.KeyStoreUtil.createKeyStoreForKeyPair;
import static net.ripe.commons.certification.util.KeyStoreUtil.getKeyPairFromKeyStore;
import static net.ripe.commons.certification.util.KeyStoreUtil.storeKeyStore;
import static net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateParser;

import org.junit.Test;

public class KeyStoreUtilTest {

	private static KeyPair TEST_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

	private KeyStore keyStore;

	private byte[] keyStoreData;

    public static final String DEFAULT_KEYSTORE_TYPE = "JKS";

    public static final String DEFAULT_KEYSTORE_PROVIDER = "SUN";


	@Test
	public void shouldKeyStoreContainExpiredCertificate() throws Exception {
	    keyStore = createKeyStoreForKeyPair(TEST_KEY_PAIR, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER, DEFAULT_SIGNATURE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);
	    keyStoreData = storeKeyStore(keyStore);

		Certificate c = keyStore.getCertificateChain(KEYSTORE_KEY_ALIAS)[0];
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse("mykeystore", c.getEncoded());
        X509ResourceCertificate certificate = parser.getCertificate();

        assertTrue(certificate.getValidityPeriod().isExpiredNow());
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

	@Test(expected=KeyStoreException.class)
	public void shouldCreateKeyStoreHandleError() throws GeneralSecurityException {
	    // non existing provider
	    createKeyStoreForKeyPair(TEST_KEY_PAIR, "foo keystore provider", DEFAULT_SIGNATURE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);
	}

	@Test(expected=KeyStoreException.class)
	public void shouldClearKeyStoreHandleError() throws GeneralSecurityException {
	    // empty keystore data
	    clearKeyStore(new byte[] {}, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER, KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE);
	}

	@Test(expected=KeyStoreException.class)
	public void shouldStoreKeyStoreHandleError() throws GeneralSecurityException {
	    // not initialized keystore
	    storeKeyStore(KeyStore.getInstance(KeyStoreUtilTest.DEFAULT_KEYSTORE_TYPE, KeyStoreUtilTest.DEFAULT_KEYSTORE_PROVIDER));
	}
}
