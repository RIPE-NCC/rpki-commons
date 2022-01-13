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
package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.PolicyInformation;
import java.time.Instant;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper.POLICY_INFORMATION;
import static org.junit.Assert.assertNull;


public class X509CertificateBuilderHelperTest {
    public final static PolicyInformation CAB_BASELINE_REQUIREMENTS_POLICY = new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.2.2"));

    private X509CertificateBuilderHelper subject;

    @Before
    public void setUp() {
        subject = new X509CertificateBuilderHelper();

        subject.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        subject.withSerial(BigInteger.ONE);
        subject.withPublicKey(TEST_KEY_PAIR.getPublic());
        subject.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        Instant now = Instant.now();
        subject.withValidityPeriod(new ValidityPeriod(now, startOfNextYear(now)));
        subject.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
    }

    public static Instant startOfNextYear(Instant now) {
        return OffsetDateTime.ofInstant(now, ZoneOffset.UTC).plusYears(1).withMonth(1).withDayOfMonth(1).truncatedTo(ChronoUnit.DAYS).toInstant();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnIncorrectAlgorithm() {
        subject.withSignatureAlgorithm("foo");
        subject.generateCertificate();
    }

    @Test
    public void shouldMakeSureTheresNoExtendedKeyUsage() throws CertificateParsingException {
        final X509Certificate x509Certificate = subject.generateCertificate();
        assertNull(x509Certificate.getExtendedKeyUsage());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnEmptyResources() {
        subject.withResources(new IpResourceSet());
        subject.generateCertificate();
    }

    @Test
    public void shouldNotFailOnOneInheritResourceType() {
        subject.withResources(new IpResourceSet());
        subject.withInheritedResourceTypes(EnumSet.of(IpResourceType.IPv4));
        subject.generateCertificate();
    }

    public void shouldAcceptArbitraryPolicyWhichShouldBeCritical() {
        // Take a non-RPKI policy
        subject.withPolicies(CAB_BASELINE_REQUIREMENTS_POLICY);
        // And ensure it is critical
        subject.generateCertificate().getCriticalExtensionOIDs().contains(CAB_BASELINE_REQUIREMENTS_POLICY.getPolicyIdentifier().toString());
    }

    @Test(expected = IllegalStateException.class)
    public void shouldFailOnRepeatedPolicies() {
        // Policy is set once (e.g. in constructor of supertype).
        subject.withPolicies(POLICY_INFORMATION);
        // And further attempts to set it are rejected (e.g. in an subtype).
        subject.withPolicies(CAB_BASELINE_REQUIREMENTS_POLICY);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnNegativeSerial() {
        subject.withSerial(BigInteger.ONE.negate());
        subject.generateCertificate();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnNeutralIntegerSerial() {
        subject.withSerial(BigInteger.ZERO);
        subject.generateCertificate();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailOnTooLargeSerial() {
        subject.withSerial(BigInteger.ONE.shiftLeft(160));
        subject.generateCertificate();
    }
}
