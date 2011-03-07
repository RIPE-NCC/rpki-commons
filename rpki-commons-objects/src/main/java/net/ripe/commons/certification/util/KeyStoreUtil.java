package net.ripe.commons.certification.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.x509cert.X509CertificateBuilder;
import net.ripe.commons.certification.x509cert.X509CertificateParser;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.io.output.NullOutputStream;
import org.joda.time.DateTime;


public final class KeyStoreUtil {

    private static final char[] KEYSTORE_PASSPHRASE = "4AD8A8BD-A001-4400-8DAC-5F3B97F07DE5".toCharArray();

    static final String KEYSTORE_KEY_ALIAS = "mykey1";


	private KeyStoreUtil() {
	    //Utility classes should not have a public or default constructor.
    }

    public static KeyStore createKeyStoreForKeyPair(KeyPair keyPair, String keyStoreProvider, String signatureProvider, String keyStoreType) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
            keyStore.load(null, KEYSTORE_PASSPHRASE);
            keyStore.aliases();
            X509ResourceCertificate certificate = createCertificate(keyPair, signatureProvider);
            keyStore.setKeyEntry(KEYSTORE_KEY_ALIAS, keyPair.getPrivate(), KEYSTORE_PASSPHRASE, new Certificate[] { certificate.getCertificate() });
            return keyStore;
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException(e);
        } catch (IOException e) {
            throw new KeyStoreException(e);
        }
    }

	public static KeyPair getKeyPairFromKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
		KeyStore keyStore = loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType);
		return getKeyPairFromKeyStore(keyStore);
	}

	public static byte[] storeKeyStore(KeyStore keyStore) {
		ByteArrayOutputStream keyStoreOS = new ByteArrayOutputStream();
		try {
			keyStore.store(keyStoreOS, KEYSTORE_PASSPHRASE);
			keyStoreOS.flush();
			return keyStoreOS.toByteArray();
		} catch (GeneralSecurityException e) {
			throw new KeyStoreException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		}
	}

	public static KeyStore clearKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
		KeyStore keyStore = loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType);
		clearKeyStore(keyStore);
		return keyStore;
	}

	private static KeyStore clearKeyStore(KeyStore keyStore) {
		try {
			if (keyStore.containsAlias(KEYSTORE_KEY_ALIAS)) {
				keyStore.deleteEntry(KEYSTORE_KEY_ALIAS);
				keyStore.store(new NullOutputStream(), KEYSTORE_PASSPHRASE);
			}
			return keyStore;
		} catch (GeneralSecurityException e) {
			throw new KeyStoreException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		}
	}

	private static KeyPair getKeyPairFromKeyStore(KeyStore keyStore) {
		try {
			Certificate c = keyStore.getCertificateChain(KEYSTORE_KEY_ALIAS)[0];
            X509CertificateParser<X509ResourceCertificate> parser = X509CertificateParser.forResourceCertificate();
            parser.parse("mykeystore", c.getEncoded());
            X509ResourceCertificate certificate = parser.getCertificate();
            PublicKey publicKey = certificate.getPublicKey();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYSTORE_KEY_ALIAS, KEYSTORE_PASSPHRASE);
            return new KeyPair(publicKey, privateKey);
		} catch (GeneralSecurityException e) {
			throw new KeyStoreException(e);
		}
	}

	private static KeyStore loadKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
    	try {
    		KeyStore keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
    		keyStore.load(new ByteArrayInputStream(keyStoreData), KEYSTORE_PASSPHRASE);
    		return keyStore;
    	} catch (GeneralSecurityException e) {
    		throw new KeyStoreException(e);
    	} catch (IOException e) {
    		throw new KeyStoreException(e);
		}
    }

	private static X509ResourceCertificate createCertificate(KeyPair keyPair, String signatureProvider) {
        X509CertificateBuilder builder = new X509CertificateBuilder();
        builder.withSignatureProvider(signatureProvider);
        builder.withSerial(BigInteger.ONE);
        builder.withValidityPeriod(new ValidityPeriod(new DateTime().minusYears(2), new DateTime().minusYears(1)));
        builder.withCa(false);
        builder.withIssuerDN(new X500Principal("CN=issuer"));
        builder.withSubjectDN(new X500Principal("CN=subject"));
        builder.withResources(IpResourceSet.parse("AS1-AS10,10/8,ffc0::/16"));
        builder.withSigningKeyPair(keyPair);
        builder.withPublicKey(keyPair.getPublic());
        return builder.buildResourceCertificate();
    }
}
