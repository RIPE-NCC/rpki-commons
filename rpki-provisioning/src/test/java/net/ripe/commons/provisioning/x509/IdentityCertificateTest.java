package net.ripe.commons.provisioning.x509;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.joda.time.DateTime;
import org.junit.Test;


public class IdentityCertificateTest {

    public static final KeyPair TEST_KEY_PAIR = generateKeyPair();

    public static final X509Certificate TEST_SELF_SIGNED_X509_CERTIFICATE = generateSelfSignedCertificate();


    @Test(expected=IllegalArgumentException.class)
    public void shouldCheckForNullArgument() {
        new IdentityCertificate(null);
    }

    @Test
    public void shouldWrapX509Certificate() {
        IdentityCertificate identityCertificate = new IdentityCertificate(TEST_SELF_SIGNED_X509_CERTIFICATE);
        assertSame(TEST_SELF_SIGNED_X509_CERTIFICATE, identityCertificate.getCertificate());
    }


    private static X509Certificate generateSelfSignedCertificate() {
        try {
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        generator.setNotBefore(new Date(new DateTime().minusDays(7).getMillis()));
        generator.setNotAfter(new Date(new DateTime().plusDays(7).getMillis()));
        generator.setIssuerDN(new X500Principal("CN=nl.blelight"));
        generator.setSerialNumber(BigInteger.ONE);
        generator.setPublicKey(TEST_KEY_PAIR.getPublic());
        generator.setSignatureAlgorithm("SHA256withRSA");
        generator.setSubjectDN(new X500Principal("CN=nl.blelight"));

        generator.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(TEST_KEY_PAIR.getPublic()));
        //TODO: check and add other extensions

        return generator.generate(TEST_KEY_PAIR.getPrivate(), "SunRsaSign");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyPair generateKeyPair() {
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
            generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
