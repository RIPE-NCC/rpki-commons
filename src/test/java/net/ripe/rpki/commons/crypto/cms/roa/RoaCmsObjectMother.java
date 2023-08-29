package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import org.bouncycastle.asn1.x509.KeyUsage;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAccessor;
import java.util.List;

import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest.CRL_DP;
import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest.TEST_ROA_LOCATION;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;

public class RoaCmsObjectMother {

    public static final Asn TEST_ASN = new Asn(65000);
    public static final RoaPrefix TEST_IPV4_PREFIX_1 = new RoaPrefix(IpRange.parse("10.64.0.0/12"), 24);
    public static final RoaPrefix TEST_IPV4_PREFIX_2 = new RoaPrefix(IpRange.parse("10.32.0.0/12"), null);
    public static final RoaPrefix TEST_IPV6_PREFIX = new RoaPrefix(IpRange.parse("2001:0:200::/39"), null);

    public static final X500Principal TEST_DN = new X500Principal("CN=Test");
    public static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;

    public static RoaCms getRoaCms(TemporalAccessor now) {
        var validityPeriod = new ValidityPeriod(now, OffsetDateTime.from(now).plusYears(1));
        return getRoaCms(validityPeriod);
    }

    public static RoaCms getRoaCms(ValidityPeriod validityPeriod) {
        return getRoaCms(validityPeriod, TEST_ASN);
    }

    public static RoaCms getRoaCms(ValidityPeriod validityPeriod, Asn asn) {
        List<RoaPrefix> prefixes = List.of(TEST_IPV4_PREFIX_1, TEST_IPV4_PREFIX_2, TEST_IPV6_PREFIX);

        return getRoaCms(prefixes, validityPeriod, asn);
    }

    public static RoaCms getRoaCms(List<RoaPrefix> prefixes, ValidityPeriod validityPeriod, Asn asn) {
        RoaCmsBuilder builder = new RoaCmsBuilder()
            .withCertificate(createCertificate(prefixes, validityPeriod))
            .withAsn(asn)
            .withPrefixes(prefixes)
            .withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
            .withClock(Clock.fixed(validityPeriod.notValidBefore(), ZoneOffset.UTC));

        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

    private static X509ResourceCertificate createCertificate(List<RoaPrefix> prefixes, ValidityPeriod validityPeriod) {
        IpResourceSet resources = new IpResourceSet();
        for (RoaPrefix prefix : prefixes) {
            resources.add(prefix.getPrefix());
        }
        X509ResourceCertificateBuilder builder = createCertificateBuilder(resources, validityPeriod);
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        return builder.build();
    }

    private static X509ResourceCertificateBuilder createCertificateBuilder(IpResourceSet resources, ValidityPeriod validityPeriod) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(BigInteger.TEN);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withValidityPeriod(validityPeriod);
        builder.withResources(resources);
        builder.withSubjectInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, TEST_ROA_LOCATION));
        builder.withKeyUsage(KeyUsage.digitalSignature);
        builder.withCrlDistributionPoints(CRL_DP);
        builder.withSubjectInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, TEST_ROA_LOCATION));
        return builder;
    }
}
