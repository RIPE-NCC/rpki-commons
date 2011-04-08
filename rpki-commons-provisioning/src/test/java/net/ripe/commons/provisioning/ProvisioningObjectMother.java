package net.ripe.commons.provisioning;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.util.Hashtable;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.util.KeyPairFactory;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.joda.time.DateTime;

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

    public static PKCS10CertificationRequest generatePkcs10CertificationRequest(int keySize, String keyName, String sigName, String provider) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyName, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

        kpg.initialize(keySize);

        KeyPair kp = kpg.genKeyPair();

        Hashtable<DERObjectIdentifier, String> attrs = new Hashtable<DERObjectIdentifier, String>();

        attrs.put(X509Name.C, "AU");
        attrs.put(X509Name.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Name.L, "Melbourne");
        attrs.put(X509Name.ST, "Victoria");
        attrs.put(X509Name.EmailAddress, "feedback-crypto@bouncycastle.org");

        Vector<DERObjectIdentifier> order = new Vector<DERObjectIdentifier>();

        order.addElement(X509Name.C);
        order.addElement(X509Name.O);
        order.addElement(X509Name.L);
        order.addElement(X509Name.ST);
        order.addElement(X509Name.EmailAddress);

        X509Name subject = new X509Name(order, attrs);

        PKCS10CertificationRequest request = new PKCS10CertificationRequest(
                sigName,
                subject,
                kp.getPublic(),
                null,
                kp.getPrivate(), DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

        return request;
    }
}
