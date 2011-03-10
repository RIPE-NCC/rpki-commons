package net.ripe.commons.provisioning;

import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;
import net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilder;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import static net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest.TEST_KEY_PAIR;

public class ProvisioningObjectMother {
    public static final KeyPair EE_KEYPAIR = ProvisioningKeyPairGenerator.generate();
    public static final X509Certificate EE_CERT = generateEECertificate();
    public static final X509CRL CRL = generateCrl();

    private static X509Certificate generateEECertificate() {
        ProvisioningCmsCertificateBuilder builder = new ProvisioningCmsCertificateBuilder();
        builder.withIssuerDN(new X500Principal("CN=nl.bluelight"));
        builder.withSerial(BigInteger.TEN);
        builder.withPublicKey(EE_KEYPAIR.getPublic());
        builder.withSubjectDN(new X500Principal("CN=nl.bluelight.end-entity"));
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        return builder.build().getCertificate();
    }

    private static X509CRL generateCrl() {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(new X500Principal("CN=nl.bluelight"));
        builder.withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic());
        DateTime now = new DateTime();
        builder.withThisUpdateTime(now);
        builder.withNextUpdateTime(now.plusHours(24));
        builder.withNumber(BigInteger.TEN);

        return builder.build(TEST_KEY_PAIR.getPrivate()).getCrl();
    }
}
