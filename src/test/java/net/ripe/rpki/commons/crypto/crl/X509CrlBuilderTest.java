package net.ripe.rpki.commons.crypto.crl;

import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.util.KeyPairUtil;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;

public class X509CrlBuilderTest {

    private static final PublicKey PUBLIC_KEY = KeyPairFactoryTest.TEST_KEY_PAIR.getPublic();
    private static final PrivateKey PRIVATE_KEY = KeyPairFactoryTest.TEST_KEY_PAIR.getPrivate();

    private static final Instant THIS_UPDATE_TIME = OffsetDateTime.of(2007, 2, 28, 2, 53, 23, 0, ZoneOffset.UTC).toInstant();
    private static final Instant NEXT_UPDATE_TIME = OffsetDateTime.of(2007, 3, 1, 2, 53, 23, 0, ZoneOffset.UTC).toInstant();
    private static final Instant REVOCATION_TIME = OffsetDateTime.of(2007, 2, 25, 19, 23, 44, 123000000, ZoneOffset.UTC).toInstant();

    private X509CrlBuilder subject;
    private X509Crl emptyCrl;
    private X509Crl nonEmptyCrl;

    @Before
    public void setUp() {
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
        assertEquals(THIS_UPDATE_TIME, emptyCrl.getThisUpdateTime());
        assertEquals(NEXT_UPDATE_TIME, emptyCrl.getNextUpdateTime());
    }

    @Test
    public void shouldUseSha256WithRsaEncryption() {
        assertEquals("SHA256withRSA", emptyCrl.getSigAlgName());
    }

    @Test
    public void shouldHaveNonNullRevokedCertificatesWhenEmpty() {
        assertNotNull(emptyCrl.getRevokedCertificates());
        assertEquals(0, emptyCrl.getRevokedCertificates().size());
    }

    @Test
    public void shouldHaveCrlEntryForRevokedCertificate() {
        X509Crl.Entry entry = nonEmptyCrl.getRevokedCertificate(BigInteger.TEN);
        assertEquals(BigInteger.TEN, entry.serialNumber());
        assertEquals(REVOCATION_TIME.truncatedTo(ChronoUnit.SECONDS), entry.revokedAt());
    }

    @Test
    public void shouldHaveTwoCrlEntriesForTwoRevokedCertificates() {
        subject.addEntry(BigInteger.ONE, REVOCATION_TIME);
        X509Crl crl = subject.build(PRIVATE_KEY);
        assertEquals(2, crl.getRevokedCertificates().size());
    }

    @Test(expected = IllegalArgumentException.class)
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

    @Test(expected = SignatureException.class)
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
        subject.addEntry(BigInteger.valueOf(42), Instant.now());
        assertFalse(subject.isSatisfiedByEntries(nonEmptyCrl));
    }

    @Test
    public void shouldNotRejectReasonableCrlNumber() {
        subject.withNumber(BigInteger.valueOf(2).pow(150));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectNegativeBigCrlNumber() {
        subject.withNumber(BigInteger.valueOf(-10));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectVeryBigCrlNumber() {
        subject.withNumber(BigInteger.valueOf(2).pow(160));
    }
}
