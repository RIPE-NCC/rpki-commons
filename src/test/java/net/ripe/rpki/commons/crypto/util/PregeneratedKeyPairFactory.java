package net.ripe.rpki.commons.crypto.util;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.crypto.x509cert.X509RouterCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509RouterCertificateBuilder;
import net.ripe.rpki.commons.util.UTC;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;

/**
 * Caches generated keys in a key store so that they can be reused in the next test run. FOR TESTING ONLY!
 */
public class PregeneratedKeyPairFactory extends KeyPairFactory {

    private static final PregeneratedKeyPairFactory RSA_INSTANCE = new PregeneratedKeyPairFactory(
            DEFAULT_RSA_KEYPAIR_GENERATOR_PROVIDER, () -> getRsaGenerator().generateKeyPair());

    private static final PregeneratedKeyPairFactory EC_INSTANCE = new PregeneratedKeyPairFactory(
            DEFAULT_EC_KEYPAIR_GENERATOR_PROVIDER, () -> getEcGenerator().generateKeyPair());

    private static final char[] PASSPHRASE = "passphrase".toCharArray();
    private final Supplier<KeyPair> kpGenerator;

    private File keyStoreFile;
    private KeyStore preGeneratedKeys;
    private int count = 0;
    private final String provider;

    private PregeneratedKeyPairFactory(String provider, Supplier<KeyPair> kpGenerator) {
        super();
        this.provider = provider;
        this.kpGenerator = kpGenerator;
        initKeyStore(provider);
    }

    private void initKeyStore(String provider) {
        try {
            keyStoreFile = new File(".pregenerated-test-key-pairs." + provider + ".keystore");
            preGeneratedKeys = KeyStore.getInstance("JKS", "SUN");
            try (InputStream input = new FileInputStream(keyStoreFile)) {
                preGeneratedKeys.load(input, PASSPHRASE);
            } catch (FileNotFoundException e) {
                preGeneratedKeys.load(null, PASSPHRASE);
            }
        } catch (final IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static PregeneratedKeyPairFactory getRsaInstance() {
        return RSA_INSTANCE;
    }

    public static PregeneratedKeyPairFactory getEcInstance() {
        return EC_INSTANCE;
    }

    @Override
    public synchronized KeyPair generate() {
        try {
            String alias = "key_" + count;
            ++count;

            PrivateKey key = (PrivateKey) preGeneratedKeys.getKey(alias, PASSPHRASE);
            KeyPair result;
            if (key == null) {
                result = kpGenerator.get();
                var certificate = createCertificate(result, provider);
                preGeneratedKeys.setKeyEntry(alias, result.getPrivate(), PASSPHRASE, new Certificate[]{certificate});
                try (final OutputStream output = new FileOutputStream(keyStoreFile)) {
                    preGeneratedKeys.store(output, PASSPHRASE);
                }
            } else {
                Certificate certificate = preGeneratedKeys.getCertificateChain(alias)[0];
                result = new KeyPair(certificate.getPublicKey(), key);
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate createCertificate(KeyPair keyPair, String provider) {
        if (provider.equals(DEFAULT_RSA_KEYPAIR_GENERATOR_PROVIDER)) {
            return createRsaCertificate(keyPair, provider).getCertificate();
        } else if (provider.equals(DEFAULT_EC_KEYPAIR_GENERATOR_PROVIDER)) {
            return createEcCertificate(keyPair, provider).getCertificate();
        } else {
            throw new IllegalArgumentException("Unknown provider " + provider);
        }
    }

    private static X509ResourceCertificate createRsaCertificate(KeyPair keyPair, String provider) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withSignatureProvider(provider);
        builder.withSerial(BigInteger.ONE);
        final DateTime now = UTC.dateTime();
        builder.withValidityPeriod(new ValidityPeriod(now.minusYears(2), now.minusYears(1)));
        builder.withCa(false);
        builder.withIssuerDN(new X500Principal("CN=issuer"));
        builder.withSubjectDN(new X500Principal("CN=subject"));
        builder.withResources(IpResourceSet.parse("AS1-AS10,10/8,ffc0::/16"));
        builder.withSigningKeyPair(keyPair);
        builder.withPublicKey(keyPair.getPublic());
        return builder.build();
    }

    private static X509RouterCertificate createEcCertificate(KeyPair keyPair, String provider) {
        X509RouterCertificateBuilder builder = new X509RouterCertificateBuilder();
        builder.withSerial(BigInteger.ONE);
        final DateTime now = UTC.dateTime();
        builder.withValidityPeriod(new ValidityPeriod(now.minusYears(2), now.minusYears(1)));
        builder.withCa(false);
        builder.withIssuerDN(new X500Principal("CN=issuer"));
        builder.withSubjectDN(new X500Principal("CN=subject"));
        builder.withSigningKeyPair(keyPair);
        builder.withAsns(new int[]{1, 2, 3});
        builder.withPublicKey(keyPair.getPublic());
        return builder.build();
    }

}
