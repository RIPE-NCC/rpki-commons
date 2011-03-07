package net.ripe.commons.certification.crl;

import static net.ripe.commons.certification.x509cert.X509CertificateBuilder.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.util.KeyPairUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;


public class X509CrlBuilderTest {

    private static final PublicKey PUBLIC_KEY = KeyPairFactoryTest.TEST_KEY_PAIR.getPublic();
    private static final PrivateKey PRIVATE_KEY = KeyPairFactoryTest.TEST_KEY_PAIR.getPrivate();

    private static final DateTime THIS_UPDATE_TIME = new DateTime(2007, 2, 28, 2, 53, 23, 0, DateTimeZone.UTC);
    private static final DateTime NEXT_UPDATE_TIME = new DateTime(2007, 3, 1, 2, 53, 23, 0, DateTimeZone.UTC);
    private static final DateTime REVOCATION_TIME = new DateTime(2007, 2, 25, 19, 23, 44, 123, DateTimeZone.UTC);

    private X509CrlBuilder subject;
    private X509Crl emptyCrl;
    private X509Crl nonEmptyCrl;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());

        subject = new X509CrlBuilder();
        subject.withIssuerDN(new X500Principal("CN=ROOT"));
        subject.withThisUpdateTime(THIS_UPDATE_TIME);
        subject.withNextUpdateTime(NEXT_UPDATE_TIME);
        subject.withNumber(BigInteger.ONE);
        subject.withAuthorityKeyIdentifier(PUBLIC_KEY);
        subject.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        emptyCrl = subject.build(PRIVATE_KEY);
        subject.addEntry(BigInteger.TEN, REVOCATION_TIME);
        nonEmptyCrl = subject.build(PRIVATE_KEY);
    }

    @Test
    public void shouldHaveVesion2() {
        assertEquals(X509CrlBuilder.CRL_VERSION_2, emptyCrl.getVersion());
    }

    @Test
    public void shouldHaveIssuer() {
        assertEquals(new X500Principal("CN=ROOT"), emptyCrl.getIssuer());
    }

    @Test
    public void shouldHaveUpdateTimes() {
        assertEquals(THIS_UPDATE_TIME, new DateTime(emptyCrl.getThisUpdateTime(), DateTimeZone.UTC));
        assertEquals(NEXT_UPDATE_TIME, new DateTime(emptyCrl.getNextUpdateTime(), DateTimeZone.UTC));
    }

    @Test
    public void shouldUseSha256WithRsaEncryption() {
        assertEquals("1.2.840.113549.1.1.11", emptyCrl.getSigAlgName());
    }

    @Test
    public void shouldHaveNonNullRevokedCertificatesWhenEmpty() {
        assertNotNull(emptyCrl.getRevokedCertificates());
        assertEquals(0, emptyCrl.getRevokedCertificates().size());
    }

    @Test
    public void shouldHaveCrlEntryForRevokedCertificate() {
        X509Crl.Entry entry = nonEmptyCrl.getRevokedCertificate(BigInteger.TEN);
        assertEquals(BigInteger.TEN, entry.getSerialNumber());
        assertEquals(REVOCATION_TIME.withMillisOfSecond(0), entry.getRevocationDateTime());
    }

    @Test
    public void shouldHaveTwoCrlEntriesForTwoRevokedCertificates() {
        subject.addEntry(BigInteger.ONE, REVOCATION_TIME);
        X509Crl crl = subject.build(PRIVATE_KEY);
        assertEquals(2, crl.getRevokedCertificates().size());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectDuplicateCrlEntriesForSameSerial() {
        subject.addEntry(BigInteger.TEN, REVOCATION_TIME);
    }

    @Test
    public void shouldHaveAuthorityKeyIdentiferExtension() {
        byte[] authorityKeyIdentifier = nonEmptyCrl.getAuthorityKeyIdentifier();
        assertNotNull(authorityKeyIdentifier);
        assertArrayEquals(KeyPairUtil.getKeyIdentifier(PUBLIC_KEY), authorityKeyIdentifier);
    }

    @Test
    public void shouldHaveCrlNumberExtension() throws IOException {
        assertEquals(BigInteger.ONE, nonEmptyCrl.getNumber());
    }

    @Test
    public void shouldVerify() throws InvalidKeyException, CRLException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        emptyCrl.verify(PUBLIC_KEY);
        nonEmptyCrl.verify(PUBLIC_KEY);
    }

    @Test(expected=SignatureException.class)
    public void shouldFailVerifyWithOtherKey() throws InvalidKeyException, CRLException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        emptyCrl.verify(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic());
    }

    @Test
    public void shouldBeSatisfiedByCrlWithSameEntries() {
        assertTrue(subject.isSatisfiedByEntries(nonEmptyCrl));
    }

    @Test
    public void shouldBeSatifisfiedByCrlWithAdditionalEntries() {
        // Additional entries should not matter, since a revoked certificate can never be "unrevoked".
        // Entries only disappear when the original certificate expires, but this does not mean we need
        // to republish a CRL.
        subject.clearEntries();
        assertTrue(subject.isSatisfiedByEntries(nonEmptyCrl));
    }

    @Test
    public void shouldNotBeSatisfiedByCrlWithFewerEntries() {
        subject.addEntry(BigInteger.valueOf(42), new DateTime());
        assertFalse(subject.isSatisfiedByEntries(nonEmptyCrl));
    }
}
