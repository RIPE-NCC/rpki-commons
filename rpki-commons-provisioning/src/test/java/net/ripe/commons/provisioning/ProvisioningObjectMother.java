package net.ripe.commons.provisioning;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.util.KeyPairFactory;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;
import net.ripe.ipresource.IpResourceSet;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;

public class ProvisioningObjectMother {

    public static final KeyPair TEST_KEY_PAIR = ProvisioningKeyPairGenerator.generate();
    public static final String DEFAULT_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";
    public static KeyPair SECOND_TEST_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

    public static final X509CRL CRL = generateCrl();

    public static final X509ResourceCertificate X509_CA = generateX509();

    private static X509ResourceCertificate generateX509() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

        builder.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        builder.withSerial(BigInteger.ONE);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = new DateTime(2011, 3, 1, 0, 0, 0, 0);
        builder.withValidityPeriod(new ValidityPeriod(now, now.plusYears(5)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        return builder.build();
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
