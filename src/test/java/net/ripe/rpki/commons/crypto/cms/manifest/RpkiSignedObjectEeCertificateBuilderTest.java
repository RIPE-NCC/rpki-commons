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
package net.ripe.rpki.commons.crypto.cms.manifest;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.RpkiSignedObjectEeCertificateBuilder;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.util.EnumSet;

import static org.junit.Assert.*;

public class RpkiSignedObjectEeCertificateBuilderTest {

    public static final int KEY_SIZE = 2048;
    public static final String DEFAULT_SIGNATURE_PROVIDER = "SunRsaSign";

    private RpkiSignedObjectEeCertificateBuilder subject;

    @Before
    public void setUp() {
        subject = new RpkiSignedObjectEeCertificateBuilder();
    }

    @Test
    public void shouldCreateEeCertificate() {
        // given
        X509ResourceCertificate resourceCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();

        URI crlUri = URI.create("rsync://somewhere/certificate.crl");
        subject.withCrlUri(crlUri);

        URI manifestUri = URI.create("rsync://somewhere/certificate.mft");
        subject.withCorrespondingCmsPublicationPoint(manifestUri);

        subject.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        subject.withPublicKey(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic());


        DateTime now = new DateTime();
        ValidityPeriod vp = new ValidityPeriod(now, now.plusSeconds(5));

        subject.withValidityPeriod(vp);

        URI publicationUri = URI.create("rsync://somewhere/certificate.cer");
        subject.withParentResourceCertificatePublicationUri(publicationUri);
        subject.withSerial(BigInteger.TEN);

        subject.withSubjectDN(new X500Principal("CN=subject"));
        subject.withIssuerDN(resourceCertificate.getSubject());

        subject.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        subject.withResources(new IpResourceSet());
        subject.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));

        // when
        X509ResourceCertificate certificate = subject.build();

        // then
        assertEquals(BigInteger.TEN, certificate.getSerialNumber());
        assertEquals(resourceCertificate.getSubject(), certificate.getIssuer());
        assertEquals(crlUri, certificate.getCrlUri());
        assertEquals(manifestUri, certificate.getSubjectInformationAccess()[0].getLocation());
        assertEquals(publicationUri, certificate.getAuthorityInformationAccess()[0].getLocation());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutSerialNumber() {
        // given
        createValidEeBuilder();
        subject.withSerial(null);

        // when
        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutResourceCertificatePublicationUri() {
        // given
        createValidEeBuilder();
        subject.withParentResourceCertificatePublicationUri(null);

        // when
        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutValidityPeriod() {
        // given
        createValidEeBuilder();
        subject.withValidityPeriod(null);

        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutIssuer() {
        // given
        createValidEeBuilder();
        subject.withIssuerDN(null);

        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutSigningKeyPair() {
        // given
        createValidEeBuilder();
        subject.withSigningKeyPair(null);

        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutManifestUri() {
        // given
        createValidEeBuilder();
        subject.withCorrespondingCmsPublicationPoint(null);

        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutCrlPublicationUri() {
        // given
        createValidEeBuilder();
        subject.withCrlUri(null);

        buildOrFail();
    }

    private void buildOrFail() {
        // when
        subject.build();

        // then
        fail("Should have thrown");
    }

    private void createValidEeBuilder() {
        X509ResourceCertificate resourceCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        URI crlUri = URI.create("rsync://somewhere/certificate.crl");
        subject.withCrlUri(crlUri);

        URI manifestUri = URI.create("rsync://somewhere/certificate.mft");
        subject.withCorrespondingCmsPublicationPoint(manifestUri);

        subject.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        subject.withIssuerDN(resourceCertificate.getSubject());

        DateTime now = new DateTime();
        subject.withValidityPeriod(new ValidityPeriod(now, now.plusSeconds(5)));

        URI publicationUri = URI.create("rsync://somewhere/certificate.cer");
        subject.withParentResourceCertificatePublicationUri(publicationUri);

        subject.withSerial(BigInteger.TEN);
    }

}
