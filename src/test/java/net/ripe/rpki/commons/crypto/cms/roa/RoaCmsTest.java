/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
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
package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlTest;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.bouncycastle.asn1.x509.KeyUsage;

import java.time.Clock;
import java.time.Instant;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParserTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;


public class RoaCmsTest {

    private Clock clock = Clock.systemUTC();
    public static final X500Principal TEST_DN = new X500Principal("CN=issuer");
    public static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;
    public static final URI TEST_ROA_LOCATION = URI.create("rsync://certificate/repository/filename.roa");
    private static final URI CRL_DP = URI.create("rsync://certificate/repository/filename.crl");
    public static final BigInteger ROA_CERT_SERIAL = BigInteger.TEN;

    private List<RoaPrefix> ipv4Prefixes;
    private List<RoaPrefix> allPrefixes;
    private IpResourceSet allResources;
    private RoaCms subject;

    public void setClock(Clock clock) {
        this.clock = clock;
    }

    @Before
    public void setUp() {
        ipv4Prefixes = new ArrayList<>();
        ipv4Prefixes.add(TEST_IPV4_PREFIX_1);
        ipv4Prefixes.add(TEST_IPV4_PREFIX_2);
        allPrefixes = new ArrayList<>(ipv4Prefixes);
        allPrefixes.add(TEST_IPV6_PREFIX);
        allResources = new IpResourceSet();
        for (RoaPrefix prefix : allPrefixes) {
            allResources.add(prefix.getPrefix());
        }
        subject = createRoaCms(clock, allPrefixes);
    }

    public static RoaCms createRoaCms(Clock clock, List<RoaPrefix> prefixes) {
        RoaCmsBuilder builder = new RoaCmsBuilder();
        builder.withCertificate(createCertificate(clock, prefixes)).withAsn(TEST_ASN);
        builder.withPrefixes(prefixes);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

    // TODO: Refactor to RoaCmsObjectMother
    public static RoaCms getRoaCms(Clock clock) {
        ArrayList<RoaPrefix> ipv4Prefixes = new ArrayList<>();
        ipv4Prefixes.add(TEST_IPV4_PREFIX_1);
        ipv4Prefixes.add(TEST_IPV4_PREFIX_2);
        ArrayList<RoaPrefix> allPrefixes = new ArrayList<>(ipv4Prefixes);
        allPrefixes.add(TEST_IPV6_PREFIX);
        IpResourceSet allResources = new IpResourceSet();
        for (RoaPrefix prefix : allPrefixes) {
            allResources.add(prefix.getPrefix());
        }
        return createRoaCms(clock, allPrefixes);
    }

    public static X509ResourceCertificate createCertificate(Clock clock, List<RoaPrefix> prefixes){
        return createCertificate(clock, prefixes, TEST_KEY_PAIR);
    }
    public static X509ResourceCertificate createCertificate(Clock clock, List<RoaPrefix> prefixes, KeyPair keyPair) {
        IpResourceSet resources = new IpResourceSet();
        for (RoaPrefix prefix : prefixes) {
            resources.add(prefix.getPrefix());
        }
        X509ResourceCertificateBuilder builder = createCertificateBuilder(clock, resources, keyPair);
        return builder.build();
    }

    private static X509ResourceCertificateBuilder createCertificateBuilder(IpResourceSet resources) {
            return createCertificateBuilder(Clock.systemUTC(), resources, TEST_KEY_PAIR);
    }
    private static X509ResourceCertificateBuilder createCertificateBuilder(Clock clock, IpResourceSet resources, KeyPair keyPair) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(ROA_CERT_SERIAL);
        builder.withPublicKey(keyPair.getPublic());
        builder.withSigningKeyPair(keyPair);
        builder.withKeyUsage(KeyUsage.digitalSignature);
        final OffsetDateTime now = OffsetDateTime.now(clock);
        builder.withValidityPeriod(new ValidityPeriod(now.minusMinutes(1).toInstant(), now.plusYears(1).toInstant()));
        builder.withResources(resources);
        builder.withCrlDistributionPoints(CRL_DP);
        builder.withSubjectInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, TEST_ROA_LOCATION));
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

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectCaCertificateInRoa() {
        X509ResourceCertificate caCert = createCertificateBuilder(new IpResourceSet(TEST_IPV4_PREFIX_1.getPrefix(), TEST_IPV4_PREFIX_2.getPrefix(), TEST_IPV6_PREFIX.getPrefix())).withCa(true).build();
        subject = new RoaCmsBuilder().withAsn(TEST_ASN).withPrefixes(allPrefixes).withCertificate(caCert).build(TEST_KEY_PAIR.getPrivate());
    }

    @Test
    public void shouldUseNotValidBeforeTimeForSigningTime() {
        RoaCms roaCms = createRoaCms(clock, allPrefixes);
        assertEquals(roaCms.getCertificate().getValidityPeriod().getNotValidBefore(), roaCms.getSigningTime());
    }

    @Test
    public void shouldPastValidityTimeForCmsBeTheSameAsTheCertificate() {
        assertEquals(subject.getCertificate().isPastValidityTime(), subject.isPastValidityTime());
    }

    @Test
    public void shouldBeRevoked() {
        CertificateRepositoryObjectValidationContext validationContext = new CertificateRepositoryObjectValidationContext(
            subject.getParentCertificateUri(), subject.getCertificate());
        X509Crl crl = X509CrlTest.getCrlBuilder(clock)
                .withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic())
                .addEntry(ROA_CERT_SERIAL, Instant.now().minus(1, ChronoUnit.DAYS))
                .build(TEST_KEY_PAIR.getPrivate());

        CrlLocator crlLocator = Mockito.mock(CrlLocator.class);
        Mockito.when(crlLocator.getCrl(Mockito.any(URI.class), Mockito.any(CertificateRepositoryObjectValidationContext.class), Mockito.any(ValidationResult.class))).thenReturn(crl);

        subject.validate(TEST_ROA_LOCATION.toString(), validationContext, crlLocator, ValidationOptions.strictValidation(), ValidationResult.withLocation(TEST_ROA_LOCATION));

        assertTrue("ROA must be revoked", subject.isRevoked());
    }

    @Test
    public void shouldNotBeRevoked() {
        CertificateRepositoryObjectValidationContext validationContext = new CertificateRepositoryObjectValidationContext(
            subject.getParentCertificateUri(), subject.getCertificate());
        X509Crl crl = X509CrlTest.getCrlBuilder(clock)
                .withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic())
                .addEntry(ROA_CERT_SERIAL.add(BigInteger.ONE), Instant.now().minus(1, ChronoUnit.DAYS))
                .build(TEST_KEY_PAIR.getPrivate());

        CrlLocator crlLocator = Mockito.mock(CrlLocator.class);
        Mockito.when(crlLocator.getCrl(Mockito.any(URI.class), Mockito.any(CertificateRepositoryObjectValidationContext.class), Mockito.any(ValidationResult.class))).thenReturn(crl);

        subject.validate(TEST_ROA_LOCATION.toString(), validationContext, crlLocator, ValidationOptions.strictValidation(), ValidationResult.withLocation(TEST_ROA_LOCATION));

        assertFalse("ROA must not be revoked", subject.isRevoked());
    }
}
