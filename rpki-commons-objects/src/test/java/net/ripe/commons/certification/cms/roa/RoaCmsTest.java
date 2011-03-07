package net.ripe.commons.certification.cms.roa;

import static net.ripe.commons.certification.cms.roa.RoaCmsParserTest.*;
import static net.ripe.commons.certification.x509cert.X509CertificateBuilder.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.x509cert.X509CertificateBuilder;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.IpResourceSet;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;


public class RoaCmsTest {

    public static final X500Principal TEST_DN = new X500Principal("CN=Test");
    public static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;

    private List<RoaPrefix> ipv4Prefixes;
    private List<RoaPrefix> allPrefixes;
    private IpResourceSet allResources;
    private RoaCms subject;


    @Before
    public void setUp() {
        ipv4Prefixes = new ArrayList<RoaPrefix>();
        ipv4Prefixes.add(TEST_IPV4_PREFIX_1);
        ipv4Prefixes.add(TEST_IPV4_PREFIX_2);
        allPrefixes = new ArrayList<RoaPrefix>(ipv4Prefixes);
        allPrefixes.add(TEST_IPV6_PREFIX);
        allResources = new IpResourceSet();
        for (RoaPrefix prefix : allPrefixes) {
            allResources.add(prefix.getPrefix());
        }
        subject = createRoaCms(allPrefixes);
    }

    public static RoaCms createRoaCms(List<RoaPrefix> prefixes) {
        RoaCmsBuilder builder = new RoaCmsBuilder();
        builder.withCertificate(createCertificate(prefixes)).withAsn(TEST_ASN);
        builder.withPrefixes(prefixes);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

    // TODO: Refactor to RoaCmsObjectMother
    public static RoaCms getRoaCms() {
    	RoaCmsTest roaCmsTest = new RoaCmsTest();
    	roaCmsTest.setUp();
    	return roaCmsTest.subject;
    }

    public static X509ResourceCertificate createCertificate(List<RoaPrefix> prefixes) {
        IpResourceSet resources = new IpResourceSet();
        for (RoaPrefix prefix : prefixes) {
            resources.add(prefix.getPrefix());
        }
        X509CertificateBuilder builder = createCertificateBuilder(resources);
        X509ResourceCertificate result = builder.buildResourceCertificate();
        return result;
    }

    private static X509CertificateBuilder createCertificateBuilder(IpResourceSet resources) {
        X509CertificateBuilder builder = new X509CertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(BigInteger.TEN);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withValidityPeriod(new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1)));
        builder.withResources(resources);
        return builder;
    }

    @Test
    public void shouldGenerateRoaCms() {
        assertEquals(TEST_ASN, subject.getAsn());
        assertEquals(allPrefixes, subject.getPrefixes());
        assertEquals(allResources, subject.getResources());
    }

    @Test
    public void shouldVerifySignature() {
        assertTrue(subject.signedBy(subject.getCertificate()));
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectCaCertificateInRoa() {
        X509ResourceCertificate caCert = createCertificateBuilder(new IpResourceSet(TEST_IPV4_PREFIX_1.getPrefix(), TEST_IPV4_PREFIX_2.getPrefix(), TEST_IPV6_PREFIX.getPrefix())).withCa(true).buildResourceCertificate();
        subject = new RoaCmsBuilder().withAsn(TEST_ASN).withPrefixes(allPrefixes).withCertificate(caCert).build(TEST_KEY_PAIR.getPrivate());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireSubjectKeyIdentifier() {
        X509ResourceCertificate cert = createCertificateBuilder(new IpResourceSet(TEST_IPV4_PREFIX_1.getPrefix(), TEST_IPV4_PREFIX_2.getPrefix(), TEST_IPV6_PREFIX.getPrefix())).withSubjectKeyIdentifier(false).buildResourceCertificate();
        subject = new RoaCmsBuilder().withAsn(TEST_ASN).withPrefixes(allPrefixes).withCertificate(cert).build(TEST_KEY_PAIR.getPrivate());
    }

    @Test
    public void shouldUseMockedTimeForSigningTime() {
        // Not using mocked time will give verification errors, which will break
        // our FitNesse test cases in the future.
        try {
            DateTime date = new DateTime(2003, 01, 01, 0, 0, 0, 0, DateTimeZone.UTC);
            DateTimeUtils.setCurrentMillisFixed(date.getMillis());
            RoaCms roaCms = createRoaCms(allPrefixes);
            assertEquals(date, roaCms.getSigningTime());
        } finally {
            DateTimeUtils.setCurrentMillisSystem();
        }
    }
}
