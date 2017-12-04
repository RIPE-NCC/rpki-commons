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
package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.PublicKey;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.*;
import static org.junit.Assert.*;

public class X509ResourceCertificateBuilderTest {

    private X509ResourceCertificateBuilder subject;

    @Before
    public void setUp() {
        subject = new X509ResourceCertificateBuilder();

        subject.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        subject.withSerial(BigInteger.ONE);
        subject.withPublicKey(TEST_KEY_PAIR.getPublic());
        subject.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = new DateTime(DateTimeZone.UTC);
        subject.withValidityPeriod(new ValidityPeriod(now, new DateTime(now.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC)));
        subject.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
    }

    @Test
    public void shouldUseOnlyTheEncodedFormOfThePublicKey() {
        PublicKey publicKey = new PublicKey() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getFormat() {
                throw new UnsupportedOperationException();
            }

            @Override
            public byte[] getEncoded() {
                return TEST_KEY_PAIR.getPublic().getEncoded();
            }

            @Override
            public String getAlgorithm() {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean equals(Object obj) {
                throw new UnsupportedOperationException();
            }
        };

        subject.withPublicKey(publicKey);

        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireResourcesForResourceCertificates() {
        subject.withResources(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireNonEmptyResourceSetForResourceCertificates() {
        subject.withResources(IpResourceSet.parse(""));
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireIssuer() {
        subject.withIssuerDN(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireSubject() {
        subject.withSubjectDN(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireSerial() {
        subject.withSerial(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequirePublicKey() {
        subject.withPublicKey(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireSigningKeyPair() {
        subject.withSigningKeyPair(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
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
    public void shouldSetBasicConstraintsForCAs() {
        subject.withCa(true);
        X509ResourceCertificate certificate = subject.build();

        assertEquals(Integer.MAX_VALUE, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldNotSetBasicConstraintsForNonCAs() {
        subject.withCa(false);
        X509ResourceCertificate certificate = subject.build();

        assertEquals(-1, certificate.getCertificate().getBasicConstraints());
    }

    @Test
    public void shouldHaveSubjectKeyIdentifierForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8"));
        subject.withSubjectKeyIdentifier(true);
        X509ResourceCertificate certificate = subject.build();

        assertNotNull(certificate.getSubjectKeyIdentifier());
    }

    @Test
    public void shouldHaveAuthorityKeyIdentifierForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8"));
        subject.withAuthorityKeyIdentifier(true);
        X509ResourceCertificate certificate = subject.build();

        assertNotNull(certificate.getAuthorityKeyIdentifier());
    }

    @Test
    public void shouldHaveResourceExtensionForResourceCertificates() {
        subject.withResources(IpResourceSet.parse("10/8, AS123"));
        X509ResourceCertificate certificate = subject.build();

        assertNotNull(certificate.getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS.getId()));
        assertNotNull(certificate.getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId()));
    }

    @Test
    public void shouldHaveKeyUsageIfSet() {
        subject.withCa(true);
        subject.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        subject.withResources(IpResourceSet.parse("10/8"));
        X509ResourceCertificate certificate = subject.build();

        assertNotNull(certificate.getCertificate().getKeyUsage());
    }

    @Test
    public void shouldHaveCrlDistributionPoints() {
        URI crlURI = URI.create("rsync://foo/bar.crl");
        subject.withCrlDistributionPoints(crlURI);
        X509ResourceCertificate certificate = subject.build();

        assertEquals(crlURI, certificate.getCrlDistributionPoints()[0]);
    }

    @Test(expected = X509ResourceCertificateBuilderException.class)
    public void shouldFailOnIncorrectProvider() {
        subject.withSignatureProvider("foo");
        subject.build();
    }


}

