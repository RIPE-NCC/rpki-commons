package net.ripe.commons.provisioning;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;

import org.joda.time.DateTime;

public class ProvisioningObjectMother {

    public static final KeyPair TEST_KEY_PAIR = ProvisioningKeyPairGenerator.generate();

    public static final X509CRL CRL = generateCrl();

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
