/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionParser;
import net.ripe.rpki.commons.util.UTC;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import static net.ripe.rpki.commons.crypto.rfc8209.RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER;
import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.SECOND_TEST_KEY_PAIR;
import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.TEST_KEY_PAIR;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class X509RouterCertificateBuilderTest {
    private X509RouterCertificateBuilder subject;

    @Before
    public void setUp() {
        subject = new X509RouterCertificateBuilder();

        subject.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        subject.withSerial(BigInteger.ONE);
        subject.withPublicKey(TEST_KEY_PAIR.getPublic());
        subject.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = UTC.dateTime();
        subject.withValidityPeriod(new ValidityPeriod(now, new DateTime(now.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC)));
        subject.withAsns(new int[]{1, 2, 3, 4, 5});
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireResourcesForResourceCertificates() {
        subject.withAsns(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireNonEmptyResourceSetForResourceCertificates() {
        subject.withAsns(new int[]{});
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireIssuer() {
        subject.withIssuerDN(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireSubject() {
        subject.withSubjectDN(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireSerial() {
        subject.withSerial(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequirePublicKey() {
        subject.withPublicKey(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireSigningKeyPair() {
        subject.withSigningKeyPair(null);
        subject.build();
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireValidityPeriod() {
        subject.withValidityPeriod(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotAllowKeyCertSignForNonCAs() {
        subject.withCa(false);
        subject.withKeyUsage(KeyUsage.keyCertSign);
        subject.build();
    }

    @Test
    public void shouldHaveExtendedKeyUsage() throws CertificateParsingException {
        final X509RouterCertificate x509RouterCertificate = subject.build();
        final List<String> extendedKeyUsage = x509RouterCertificate.getCertificate().getExtendedKeyUsage();
        assertEquals(1, extendedKeyUsage.size());
        assertEquals(OID_KP_BGPSEC_ROUTER.toString(), extendedKeyUsage.get(0));
    }

    @Test
    public void shouldIgnoreBasicConstraintsForCAs() {
        subject.withCa(true);
        X509RouterCertificate certificate = subject.build();
        assertEquals(-1, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldNotSetBasicConstraintsForNonCAs() {
        subject.withCa(false);
        X509RouterCertificate certificate = subject.build();
        assertEquals(-1, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldHaveCrlDistributionPoints() {
        URI crlURI = URI.create("rsync://foo/bar.crl");
        subject.withCrlDistributionPoints(crlURI);
        X509RouterCertificate certificate = subject.build();

        assertEquals(crlURI, certificate.getCrlDistributionPoints()[0]);
    }

    @Test
    public void shouldHaveAsnExtension() {
        subject.withAsns(new int[]{1, 22, 333});
        X509RouterCertificate certificate = subject.build();

        byte[] asnExtension = certificate.getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId());
        final IpResourceSet asResources = new ResourceExtensionParser().parseAsIdentifiers(asnExtension);
        assertEquals(IpResourceSet.parse("AS1, AS22, AS333"), asResources);
    }

    @Test
    public void shouldHaveBgpExtension() {
        subject.withAsns(new int[]{1, 22, 333});
        X509RouterCertificate certificate = subject.build();
        assertTrue(certificate.isRouter());
    }

    @Test(expected = X509ResourceCertificateBuilderException.class)
    public void shouldFailOnIncorrectProvider() {
        subject.withSignatureProvider("foo");
        subject.build();
    }
}
