package net.ripe.commons.certification.cms.roa;

import static net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;

import org.joda.time.DateTime;

public class RoaCmsObjectMother {

    public static final Asn TEST_ASN = new Asn(Long.valueOf(65000));
    public static final RoaPrefix TEST_IPV4_PREFIX_1 = new RoaPrefix(IpRange.parse("10.64.0.0/12"), 24);
    public static final RoaPrefix TEST_IPV4_PREFIX_2 = new RoaPrefix(IpRange.parse("10.32.0.0/12"), null);
    public static final RoaPrefix TEST_IPV6_PREFIX = new RoaPrefix(IpRange.parse("2001:0:200::/39"), null);

    public static final X500Principal TEST_DN = new X500Principal("CN=Test");
    public static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;

    public static RoaCms getRoaCms() {
        ValidityPeriod validityPeriod = new ValidityPeriod(new DateTime(), new DateTime().plusYears(1));
        return getRoaCms(validityPeriod);
    }

    public static RoaCms getRoaCms(ValidityPeriod validityPeriod) {
        return getRoaCms(validityPeriod, TEST_ASN);
    }

    public static RoaCms getRoaCms(ValidityPeriod validityPeriod, Asn asn) {
        List<RoaPrefix> ipv4Prefixes;
        List<RoaPrefix> allPrefixes;

        ipv4Prefixes = new ArrayList<RoaPrefix>();
        ipv4Prefixes.add(TEST_IPV4_PREFIX_1);
        ipv4Prefixes.add(TEST_IPV4_PREFIX_2);

        allPrefixes = new ArrayList<RoaPrefix>(ipv4Prefixes);
        allPrefixes.add(TEST_IPV6_PREFIX);

        return getRoaCms(allPrefixes, validityPeriod, asn);
    }

    public static RoaCms getRoaCms(List<RoaPrefix> prefixes, ValidityPeriod validityPeriod, Asn asn) {
        RoaCmsBuilder builder = new RoaCmsBuilder();
        builder.withCertificate(createCertificate(prefixes, validityPeriod));
        builder.withAsn(asn);
        builder.withPrefixes(prefixes);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

    private static X509ResourceCertificate createCertificate(List<RoaPrefix> prefixes, ValidityPeriod validityPeriod) {
        IpResourceSet resources = new IpResourceSet();
        for (RoaPrefix prefix : prefixes) {
            resources.add(prefix.getPrefix());
        }
        X509ResourceCertificateBuilder builder = createCertificateBuilder(resources, validityPeriod);
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        X509ResourceCertificate result = builder.buildResourceCertificate();
        return result;
    }

    private static X509ResourceCertificateBuilder createCertificateBuilder(IpResourceSet resources, ValidityPeriod validityPeriod) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(BigInteger.TEN);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withValidityPeriod(validityPeriod);
        builder.withResources(resources);
        return builder;
    }
}
