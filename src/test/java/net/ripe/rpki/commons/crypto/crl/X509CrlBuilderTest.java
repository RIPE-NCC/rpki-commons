/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.crypto.crl;

import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.util.KeyPairUtil;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
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

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;

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
        assertEquals(BigInteger.TEN, entry.getSerialNumber());
        assertEquals(REVOCATION_TIME.withMillisOfSecond(0), entry.getRevocationDateTime());
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
        subject.addEntry(BigInteger.valueOf(42), new DateTime());
        assertFalse(subject.isSatisfiedByEntries(nonEmptyCrl));
    }
}
