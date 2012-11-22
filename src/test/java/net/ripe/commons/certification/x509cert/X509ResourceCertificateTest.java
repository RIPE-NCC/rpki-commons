/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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
package net.ripe.commons.certification.x509cert;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.EnumSet;
import javax.security.auth.x500.X500Principal;
import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlTest;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationOptions;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.easymock.IAnswer;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;


public class X509ResourceCertificateTest {

    private static final URI CERT_URI = URI.create("rsync://host.foo/bar/ta.cer");
    private static final ValidationLocation CERT_URI_VALIDATION_LOCATION = new ValidationLocation(CERT_URI);

    private static final URI CRL_DP = URI.create("rsync://host/foo/crl");
    private static final ValidationLocation CRL_DP_VALIDATION_LOCATION = new ValidationLocation(CRL_DP);
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
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY,
                        URI.create("rsync://foo.host/bar/")),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY,
                        URI.create("http://foo.host/bar/"))};
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
        crlLocator = createMock(CrlLocator.class);
    }

    @Test(expected=IllegalArgumentException.class)
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

    @Test(expected=SignatureException.class)
    public void shouldFailOnInvalidSignature() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        X509ResourceCertificate certificate = createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET);
        certificate.getCertificate().verify(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic());
    }

    @Test
    public void shouldIgnoreCrlWhenValidatingRootCertificate() {
        ValidationResult result = new ValidationResult();
        X509ResourceCertificate selfSignedCert = createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET);
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(CERT_URI, selfSignedCert);
        replay(crlLocator);

        selfSignedCert.validate(CERT_URI.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        verify(crlLocator);
    }

    @Test
    public void shouldFailWhenCrlCannotBeLocated() {
        final ValidationResult result = new ValidationResult();
        X509ResourceCertificate rootCertificate = createSelfSignedCaResourceCertificate();
        X509ResourceCertificate subject = createSelfSignedCaResourceCertificateBuilder()
            .withPublicKey(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic())
            .withSubjectDN(new X500Principal("CN=child"))
            .withCrlDistributionPoints(CRL_DP)
            .build();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(CERT_URI, rootCertificate);

        expect(crlLocator.getCrl(CRL_DP, context, result)).andAnswer(new IAnswer<X509Crl>() {
           @Override
        public X509Crl answer() throws Throwable {

            assertEquals(CRL_DP_VALIDATION_LOCATION, result.getCurrentLocation());
               result.rejectIfFalse(false, ValidationString.CRL_SIGNATURE_VALID);
               return null;
            }
        });
        replay(crlLocator);

        result.setLocation(new ValidationLocation(CERT_URI));
        subject.validate(CERT_URI.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        verify(crlLocator);
        assertEquals(CERT_URI_VALIDATION_LOCATION, result.getCurrentLocation());
        assertTrue("certificate should have errors", result.hasFailureForCurrentLocation());
        assertTrue("crl should have errors", result.hasFailureForLocation(CRL_DP_VALIDATION_LOCATION));
    }

    @Test
    public void shouldValidateWhenCrlOk() {
        final ValidationResult result = new ValidationResult();
        X509ResourceCertificate rootCertificate = createSelfSignedCaResourceCertificate();
        X509ResourceCertificate subject = createSelfSignedCaResourceCertificateBuilder()
            .withPublicKey(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic())
            .withSubjectDN(new X500Principal("CN=child"))
            .withCrlDistributionPoints(CRL_DP)
            .build();
        X509Crl crl = X509CrlTest.createCrl();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(CERT_URI, rootCertificate);

        expect(crlLocator.getCrl(CRL_DP, context, result)).andReturn(crl);
        replay(crlLocator);

        subject.validate(CERT_URI.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        verify(crlLocator);
        assertEquals(CERT_URI_VALIDATION_LOCATION, result.getCurrentLocation());
        assertEquals("[]", result.getFailuresForCurrentLocation().toString());
        assertFalse(result.hasFailureForLocation(CERT_URI_VALIDATION_LOCATION));
    }
}
