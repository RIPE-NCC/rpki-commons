package net.ripe.rpki.commons.crypto.util;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
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
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Caches generated keys in a key store so that they can be reused in the next test run. FOR TESTING ONLY!
 */
public final class PregeneratedKeyPairFactory extends KeyPairFactory {

    private static final PregeneratedKeyPairFactory INSTANCE = new PregeneratedKeyPairFactory();

    private static final char[] PASSPHRASE = "passphrase".toCharArray();

    private final File keyStoreFile = new File(".pregenerated-test-key-pairs.keystore");
    private KeyStore pregeneratedKeys;

    private int count = 0;

    private PregeneratedKeyPairFactory() {
        super();
        initKeyStore();
    }

    private void initKeyStore() {
        try {
            pregeneratedKeys = KeyStore.getInstance("JKS", "SUN");
            try (InputStream input = new FileInputStream(keyStoreFile)) {
                pregeneratedKeys.load(input, PASSPHRASE);
            } catch (FileNotFoundException e) {
                pregeneratedKeys.load(null, PASSPHRASE);
            }
        } catch (final IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static PregeneratedKeyPairFactory getInstance() {
        return INSTANCE;
    }

    @Override
    public KeyPair generateEC() {
        return generateImpl(super::generateEC, PregeneratedKeyPairFactory::createECCertificate);
    }

    @Override
    public KeyPair generate() {
        return generateImpl(super::generate, PregeneratedKeyPairFactory::createCertificate);
    }

    public synchronized KeyPair generateImpl(Supplier<KeyPair> keyPairSupplier, Function<KeyPair, X509ResourceCertificate> makeCert) {
        try {
            String alias = "key_" + count;
            ++count;

            PrivateKey key = (PrivateKey) pregeneratedKeys.getKey(alias, PASSPHRASE);
            KeyPair result;
            if (key == null) {
                result = keyPairSupplier.get();
                var certificate = makeCert.apply(result).getCertificate();
                pregeneratedKeys.setKeyEntry(alias, result.getPrivate(), PASSPHRASE, new Certificate[]{certificate});
                try (final OutputStream output = new FileOutputStream(keyStoreFile)) {
                    pregeneratedKeys.store(output, PASSPHRASE);
                }
            } else {
                Certificate certificate = pregeneratedKeys.getCertificateChain(alias)[0];
                result = new KeyPair(certificate.getPublicKey(), key);
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static X509ResourceCertificate createCertificate(KeyPair keyPair) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withSignatureProvider(DEFAULT_RSA_KEYPAIR_GENERATOR_PROVIDER);
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

    private static X509ResourceCertificate createECCertificate(KeyPair keyPair) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withSignatureProvider(DEFAULT_EC_KEYPAIR_GENERATOR_PROVIDER);
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
}
