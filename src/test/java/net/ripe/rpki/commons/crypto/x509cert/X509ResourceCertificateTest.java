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
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlTest;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.EnumSet;
import java.util.Random;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


public class X509ResourceCertificateTest {

    public static final URI TEST_TA_URI = URI.create("rsync://host.foo/ta.cer");
    public static final URI TEST_CA_URI = URI.create("rsync://host.foo/ca.cer");
    private static final ValidationLocation CERT_URI_VALIDATION_LOCATION = new ValidationLocation(TEST_TA_URI);

    public static final URI TEST_TA_CRL = URI.create("rsync://host.foo/bar/ta.crl");
    private static final URI MFT_URI = URI.create("rsync://host.foo/bar/ta.mft");
    private static final URI PUB_DIR_URI = URI.create("rsync://host.foo/bar/");


    private static final ValidationLocation CRL_DP_VALIDATION_LOCATION = new ValidationLocation(TEST_TA_CRL);
    public static final X500Principal TEST_SELF_SIGNED_CERTIFICATE_NAME = new X500Principal("CN=TEST-SELF-SIGNED-CERT");
    private static final IpResourceSet TEST_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private CrlLocator crlLocator;

    private static final ValidityPeriod TEST_VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(100));
    private static final BigInteger TEST_SERIAL_NUMBER = BigInteger.valueOf(900);

    private static final ValidationOptions VALIDATION_OPTIONS = new ValidationOptions();

    public static X509ResourceCertificateBuilder createSelfSignedCaCertificateBuilder() {
        X509ResourceCertificateBuilder builder = createBasicBuilder();
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        return builder;
    }

    public static X509ResourceCertificateBuilder createBasicBuilder() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withSerial(TEST_SERIAL_NUMBER);
        builder.withValidityPeriod(TEST_VALIDITY_PERIOD);
        builder.withPublicKey(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        builder.withAuthorityKeyIdentifier(true);

        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, PUB_DIR_URI),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, MFT_URI)};
        builder.withSubjectInformationAccess(descriptors);

        return builder;
    }


    public static X509ResourceCertificate createSelfSignedCaResourceCertificate() {
        return createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET);
    }

    public static X509ResourceCertificate createSelfSignedCaResourceCertificate(IpResourceSet ipResourceSet) {
        X509ResourceCertificateBuilder builder = createSelfSignedCaResourceCertificateBuilder().withResources(ipResourceSet);
        return builder.build();
    }

    public static X509ResourceCertificate createSelfSignedCaResourceCertificate(KeyPair keyPair) {
        X509ResourceCertificateBuilder builder = createSelfSignedCaResourceCertificateBuilder().withResources(TEST_RESOURCE_SET).withSigningKeyPair(keyPair).withPublicKey(keyPair.getPublic());
        return builder.build();
    }

    public static X509ResourceCertificateBuilder createSelfSignedCaResourceCertificateBuilder() {
        return createSelfSignedCaCertificateBuilder()
                .withResources(TEST_RESOURCE_SET)
                .withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME)
                .withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
    }

    public static X509ResourceCertificateBuilder createSelfSignedEeCertificateBuilder() {
        return createBasicBuilder().withCa(false)
                .withResources(TEST_RESOURCE_SET)
                .withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME)
                .withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
    }

    @Before
    public void setUp() {
        crlLocator = mock(CrlLocator.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireCertificate() {
        new X509ResourceCertificate(null);
    }

    @Test
    public void shouldHaveCertificate() {
        assertNotNull(createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET).getCertificate());
    }

    @Test
    public void shouldDecodeResourceExtensions() {
        assertEquals(TEST_RESOURCE_SET, createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET).getResources());
    }

    @Test
    public void shouldSupportResourceInheritance() {
        X509ResourceCertificate inherited = createSelfSignedCaResourceCertificateBuilder().withResources(new IpResourceSet()).withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class)).build();
        assertTrue(inherited.isResourceSetInherited());
        assertTrue(inherited.getResources().isEmpty());
        assertFalse(createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET).isResourceSetInherited());

        assertEquals("AS21212, 10.0.0.0/8, 192.168.0.0/16, ffce::/16", inherited.deriveResources(TEST_RESOURCE_SET).toString());
    }

    @Test
    public void shouldSupportInheritedAsnsOnly() {
        X509ResourceCertificate subject = createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.parse("10.0.0.0/8")).withInheritedResourceTypes(EnumSet.of(IpResourceType.ASN)).build();

        assertTrue(subject.isResourceTypesInherited(EnumSet.of(IpResourceType.ASN)));
        assertFalse(subject.isResourceTypesInherited(EnumSet.of(IpResourceType.IPv4)));
        assertFalse(subject.isResourceTypesInherited(EnumSet.of(IpResourceType.IPv6)));
        assertTrue(subject.isResourceSetInherited());

        assertEquals("AS21212, 10.0.0.0/8", subject.deriveResources(TEST_RESOURCE_SET).toString());
    }

    @Test
    public void shouldSupportInheritedIpAddressesOnly() {
        X509ResourceCertificate subject = createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.parse("AS1234")).withInheritedResourceTypes(EnumSet.of(IpResourceType.IPv4, IpResourceType.IPv6)).build();

        assertFalse(subject.isResourceTypesInherited(EnumSet.of(IpResourceType.ASN)));
        assertTrue(subject.isResourceTypesInherited(EnumSet.of(IpResourceType.IPv4)));
        assertTrue(subject.isResourceTypesInherited(EnumSet.of(IpResourceType.IPv6)));
        assertTrue(subject.isResourceSetInherited());

        assertEquals("AS1234, 10.0.0.0/8, 192.168.0.0/16, ffce::/16", subject.deriveResources(TEST_RESOURCE_SET).toString());
    }

    @Test
    public void shouldSupportCaCertificate() {
        X509ResourceCertificate resourceCertificate = createSelfSignedEeCertificateBuilder().build();
        assertTrue(resourceCertificate.isEe());
        assertFalse(resourceCertificate.isCa());

        X509ResourceCertificate cert = createSelfSignedCaResourceCertificateBuilder().build();
        assertTrue(cert.isCa());
        assertFalse(cert.isEe());
    }

    @Test
    public void shouldSupportAuthorityInformationAccessExtension() throws URISyntaxException {
        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, new URI("rsync://foo.host/bar/baz.cer")),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, new URI("http://foo.host/bar/baz.cer"))
        };
        X509ResourceCertificateBuilder builder = createSelfSignedEeCertificateBuilder();
        builder.withAuthorityInformationAccess(descriptors);
        X509ResourceCertificate cert = builder.build();
        assertArrayEquals(descriptors, cert.getAuthorityInformationAccess());

        assertEquals(descriptors[0].getLocation(), cert.findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS));
        assertNull(cert.findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST));
        assertNotNull(cert.findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS));
    }

    @Test
    public void shouldSupportSubjectInformationAccessExtension() throws URISyntaxException {
        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, new URI("rsync://foo.host/bar/")),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, new URI("http://foo.host/bar/"))
        };
        X509ResourceCertificateBuilder builder = createSelfSignedEeCertificateBuilder();
        builder.withSubjectInformationAccess(descriptors);
        X509ResourceCertificate cert = builder.build();
        assertArrayEquals(descriptors, cert.getSubjectInformationAccess());
        assertNotNull(cert.findFirstSubjectInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY));
    }

    @Test
    public void shouldSupportCrlDistributionPoints() {
        URI[] crlDistributionPoints = {
                URI.create("rsync://localhost/ca.crl")
        };
        X509ResourceCertificateBuilder builder = createSelfSignedEeCertificateBuilder();
        builder.withCrlDistributionPoints(crlDistributionPoints);
        X509ResourceCertificate cert = builder.build();
        assertArrayEquals(crlDistributionPoints, cert.getCrlDistributionPoints());
        assertNotNull(cert.findFirstRsyncCrlDistributionPoint());
    }

    /**
     * See http://tools.ietf.org/html/draft-ietf-sidr-res-certs-13#section-3.9.8
     */
    @Test
    public void shouldHaveCertificatePolicy() {
        X509ResourceCertificate cert = createSelfSignedCaResourceCertificate();
        assertEquals(AbstractX509CertificateWrapper.POLICY_OID, cert.getCertificatePolicy());
    }

    @Test
    public void shouldHaveValidSignature() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        X509ResourceCertificate certificate = createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET);
        certificate.getCertificate().verify(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
    }

    @Test(expected = SignatureException.class)
    public void shouldFailOnInvalidSignature() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        X509ResourceCertificate certificate = createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET);
        certificate.getCertificate().verify(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic());
    }

    @Test
    public void shouldIgnoreCrlWhenValidatingRootCertificate() {
        ValidationResult result = ValidationResult.withLocation(TEST_TA_URI);
        X509ResourceCertificate selfSignedCert = createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET);
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(TEST_TA_URI, selfSignedCert);

        selfSignedCert.validate(TEST_TA_URI.toString(), context, crlLocator, VALIDATION_OPTIONS, result);
    }

    @Test
    public void shouldFailWhenCrlCannotBeLocated() {
        final ValidationResult result = ValidationResult.withLocation(TEST_TA_URI);
        X509ResourceCertificate rootCertificate = createSelfSignedCaResourceCertificate();
        X509ResourceCertificate subject = createSelfSignedCaResourceCertificateBuilder()
                .withPublicKey(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic())
                .withSubjectDN(new X500Principal("CN=child"))
                .withCrlDistributionPoints(TEST_TA_CRL)
                .build();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(TEST_TA_URI, rootCertificate);

        when(crlLocator.getCrl(TEST_TA_CRL, context, result)).thenAnswer(new Answer<X509Crl>() {
            @Override
            public X509Crl answer(InvocationOnMock invocationOnMock) throws Throwable {
                assertEquals(CRL_DP_VALIDATION_LOCATION, result.getCurrentLocation());
                result.rejectIfFalse(false, ValidationString.CRL_SIGNATURE_VALID);
                return null;
            }
        });

        result.setLocation(new ValidationLocation(TEST_TA_URI));
        subject.validate(TEST_TA_URI.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertEquals(CERT_URI_VALIDATION_LOCATION, result.getCurrentLocation());
        assertTrue("certificate should have errors", result.hasFailureForCurrentLocation());
        assertTrue("crl should have errors", result.hasFailureForLocation(CRL_DP_VALIDATION_LOCATION));
    }

    @Test
    public void shouldValidateWhenCrlOk() {
        final ValidationResult result = ValidationResult.withLocation(TEST_TA_URI);
        X509ResourceCertificate rootCertificate = createSelfSignedCaResourceCertificate();
        X509ResourceCertificate subject = createSelfSignedCaResourceCertificateBuilder()
                .withPublicKey(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic())
                .withSubjectDN(new X500Principal("CN=child"))
                .withCrlDistributionPoints(TEST_TA_CRL)
                .build();
        X509Crl crl = X509CrlTest.createCrl();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(TEST_TA_URI, rootCertificate);

        when(crlLocator.getCrl(TEST_TA_CRL, context, result)).thenReturn(crl);

        subject.validate(TEST_TA_URI.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertEquals(CERT_URI_VALIDATION_LOCATION, result.getCurrentLocation());
        assertEquals("[]", result.getFailuresForCurrentLocation().toString());
        assertFalse(result.hasFailureForLocation(CERT_URI_VALIDATION_LOCATION));
    }

    @Test
    public void shouldReturnImmutableResources() {
        X509ResourceCertificate cert = createSelfSignedCaResourceCertificate();

        IpResourceSet resources = cert.getResources();
        resources.removeAll(new IpResourceSet(resources));

        assertFalse(cert.getResources().isEmpty());
    }

    @Test
    public void shouldNotBePastValidityTime() {
        X509ResourceCertificate cert = createSelfSignedCaResourceCertificate();
        assertEquals(cert.getValidityPeriod().isExpiredNow(), cert.isPastValidityTime());
    }

    @Test
    @Ignore("Production code not implemented")
    public void shouldBeRevoked() {
        X509ResourceCertificate rootCert = createSelfSignedCaResourceCertificateBuilder()
                .withResources(TEST_RESOURCE_SET)
                .withCrlDistributionPoints(TEST_TA_CRL)
                .build();
        BigInteger serialNumber = BigInteger.valueOf(new Random(new DateTime().getMillis()).nextLong());

        X509ResourceCertificate subject = createBasicBuilder()
                .withResources(TEST_RESOURCE_SET)
                .withSerial(serialNumber)
                .build();

        X509Crl crl = X509CrlTest.getCrlBuilder()
                .withAuthorityKeyIdentifier(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic())
                .addEntry(serialNumber, DateTime.now().minusDays(1))
                .build(KeyPairFactoryTest.TEST_KEY_PAIR.getPrivate());

        CrlLocator crlLocator = Mockito.mock(CrlLocator.class);
        Mockito.when(crlLocator.getCrl(Mockito.any(URI.class), Mockito.any(CertificateRepositoryObjectValidationContext.class), Mockito.any(ValidationResult.class))).thenReturn(crl);

        CertificateRepositoryObjectValidationContext validationContext = new CertificateRepositoryObjectValidationContext(TEST_TA_URI, rootCert);

        subject.validate(TEST_CA_URI.toString(), validationContext, crlLocator, new ValidationOptions(), ValidationResult.withLocation(TEST_CA_URI));

        assertTrue("Certificate must be revoked", subject.isRevoked());

    }
}
