package net.ripe.rpki.commons.crypto.util;

import com.google.common.io.ByteStreams;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import net.ripe.rpki.commons.util.UTC;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.BiConsumer;
import java.util.function.Consumer;


public final class KeyStoreUtil {

    public static final char[] KEYSTORE_PASSPHRASE = "4AD8A8BD-A001-4400-8DAC-5F3B97F07DE5".toCharArray();

    static final String KEYSTORE_KEY_ALIAS = "mykey1";


    private KeyStoreUtil() {
        //Utility classes should not have a public or default constructor.
    }

    public static KeyStore createKeyStoreForKeyPair(KeyPair keyPair, String keyStoreProvider, String signatureProvider, String keyStoreType) {
        return createKeyStoreForKeyPair(keyPair, keyStoreProvider, signatureProvider, keyStoreType, KeyStoreUtil::defaultLoadKeyStore);
    }

    private static void defaultLoadKeyStore(KeyStore keyStore) {
        try {
            keyStore.load(null, KEYSTORE_PASSPHRASE);
        } catch (GeneralSecurityException | IOException e) {
            throw new KeyStoreException(e);
        }
    }

    public static KeyStore createKeyStoreForKeyPair(final KeyPair keyPair,
                                                    final String keyStoreProvider,
                                                    final String signatureProvider,
                                                    final String keyStoreType,
                                                    final Consumer<KeyStore> loadKs) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
            loadKs.accept(keyStore);
            keyStore.aliases();
            X509Certificate certificate = generateCertificate(keyPair, signatureProvider);
            keyStore.setKeyEntry(KEYSTORE_KEY_ALIAS, keyPair.getPrivate(), KEYSTORE_PASSPHRASE, new Certificate[]{certificate});
            return keyStore;
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException(e);
        }
    }

    public static KeyPair getKeyPairFromKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
        KeyStore keyStore = loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType);
        return getKeyPairFromKeyStore(keyStore);
    }

    public static KeyPair getKeyPairFromKeyStore(byte[] keyStoreData,
                                                 String keyStoreProvider,
                                                 String keyStoreType,
                                                 final BiConsumer<KeyStore, InputStream> loadKs) {
        KeyStore keyStore = loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType, loadKs);
        return getKeyPairFromKeyStore(keyStore);
    }

    public static byte[] storeKeyStore(KeyStore keyStore) {
        ByteArrayOutputStream keyStoreOS = new ByteArrayOutputStream();
        try {
            keyStore.store(keyStoreOS, KEYSTORE_PASSPHRASE);
            keyStoreOS.flush();
            return keyStoreOS.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            throw new KeyStoreException(e);
        }
    }

    public static KeyStore clearKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
        return clearKeyStore(loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType));
    }

    public static void clearKeyStore(byte[] keyStoreData,
                                     String keyStoreProvider,
                                     String keyStoreType,
                                     final BiConsumer<KeyStore, InputStream> loadKs) {
        clearKeyStore(loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType, loadKs));
    }

    private static KeyStore clearKeyStore(KeyStore keyStore) {
        try {
            if (keyStore.containsAlias(KEYSTORE_KEY_ALIAS)) {
                keyStore.deleteEntry(KEYSTORE_KEY_ALIAS);
                keyStore.store(ByteStreams.nullOutputStream(), KEYSTORE_PASSPHRASE);
            }
            return keyStore;
        } catch (GeneralSecurityException | IOException e) {
            throw new KeyStoreException(e);
        }
    }

    private static KeyPair getKeyPairFromKeyStore(KeyStore keyStore) {
        try {
            Certificate certificate = keyStore.getCertificateChain(KEYSTORE_KEY_ALIAS)[0];
            PublicKey publicKey = certificate.getPublicKey();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYSTORE_KEY_ALIAS, KEYSTORE_PASSPHRASE);
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException(e);
        }
    }

    private static KeyStore loadKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
        return loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType, (keyStore, is) -> {
            try {
                keyStore.load(new ByteArrayInputStream(keyStoreData), KEYSTORE_PASSPHRASE);
            } catch (Exception e) {
                throw new KeyStoreException(e);
            }
        });
    }

    private static KeyStore loadKeyStore(byte[] keyStoreData,
                                         String keyStoreProvider,
                                         String keyStoreType,
                                         final BiConsumer<KeyStore, InputStream> loadKs) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
            loadKs.accept(keyStore, new ByteArrayInputStream(keyStoreData));
            return keyStore;
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException(e);
        }
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String signatureProvider) {
        DateTime now = UTC.dateTime();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=issuer"),
                BigInteger.ONE,
                now.minusYears(2).toDate(),
                now.minusYears(1).toDate(),
                new X500Principal("CN=subject"),
                keyPair.getPublic());
        try {
            ContentSigner sigGen = new JcaContentSignerBuilder(X509CertificateBuilderHelper.DEFAULT_SIGNATURE_ALGORITHM)
                    .setProvider(signatureProvider)
                    .build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(builder.build(sigGen));
        } catch (OperatorCreationException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
