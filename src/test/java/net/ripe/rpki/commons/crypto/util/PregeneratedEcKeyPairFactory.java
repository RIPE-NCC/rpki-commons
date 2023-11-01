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

/**
 * Caches generated keys in a key store so that they can be reused in the next test run. FOR TESTING ONLY!
 */
public final class PregeneratedEcKeyPairFactory extends EcKeyPairFactory {

    private static final PregeneratedEcKeyPairFactory INSTANCE = new PregeneratedEcKeyPairFactory("SunEC");

    private static final char[] PASSPHRASE = "passphrase".toCharArray();

    private File keyStoreFile;

    private KeyStore pregeneratedKeys;

    private int count = 0;

    private PregeneratedEcKeyPairFactory(String provider) {
        super(provider);
        keyStoreFile =  new File(".pregenerated-test-key-pairs-ec-" + provider + ".keystore");
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

    public static PregeneratedEcKeyPairFactory getInstance() {
        return INSTANCE;
    }

    @Override
    public EcKeyPairFactory withProvider(String provider) {
        return this;
    }

    @Override
    public synchronized KeyPair generate() {
        try {
            String alias = "key_" + count;
            ++count;

            PrivateKey key = (PrivateKey) pregeneratedKeys.getKey(alias, PASSPHRASE);
            KeyPair result;
            if (key == null) {
                result = super.generate();
                pregeneratedKeys.setKeyEntry(alias, result.getPrivate(), PASSPHRASE, new Certificate[]{createCertificate(result).getCertificate()});
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
        builder.withSignatureProvider("SunEC");
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

    private static X509ResourceCertificate createEcCertificate(KeyPair keyPair) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withSignatureProvider("EC");
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
