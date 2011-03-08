package net.ripe.commons.certification.x509cert;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlTest;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.easymock.IAnswer;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;


public class X509ResourceCertificateTest {

	private static final URI CERT_URI = URI.create("rsync://host.foo/bar/ta.cer");
	private static final URI CRL_DP = URI.create("rsync://host/foo/crl");
    public static final X500Principal TEST_SELF_SIGNED_CERTIFICATE_NAME = new X500Principal("CN=TEST-SELF-SIGNED-CERT");
    private static final IpResourceSet TEST_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private CrlLocator crlLocator;
    
    private static final ValidityPeriod TEST_VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(100));
    private static final BigInteger TEST_SERIAL_NUMBER = BigInteger.valueOf(900);

    public static X509ResourceCertificateBuilder createSelfSignedCaCertificateBuilder() {
        X509ResourceCertificateBuilder builder = createBasicBuilder();
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign);
        return builder;
    }

    private static X509ResourceCertificateBuilder createBasicBuilder() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withSerial(TEST_SERIAL_NUMBER);
        builder.withValidityPeriod(TEST_VALIDITY_PERIOD);
        builder.withPublicKey(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        builder.withAuthorityKeyIdentifier(true);
        return builder;
    }
    

    public static X509ResourceCertificate createSelfSignedCaResourceCertificate() {
        return createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET);
    }

    public static X509ResourceCertificate createSelfSignedCaResourceCertificate(IpResourceSet ipResourceSet) {
            X509ResourceCertificateBuilder builder = createSelfSignedCaResourceCertificateBuilder().withResources(ipResourceSet);
            return builder.buildResourceCertificate();
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
        X509ResourceCertificate inherited = createSelfSignedCaResourceCertificateBuilder().withResources(InheritedIpResourceSet.getInstance()).buildResourceCertificate();
        assertTrue(inherited.isResourceSetInherited());
        assertTrue(inherited.getResources() instanceof InheritedIpResourceSet);
        assertFalse(createSelfSignedCaResourceCertificate(TEST_RESOURCE_SET).isResourceSetInherited());
    }

    @Test
    public void shouldSupportCaCertificate() {
        X509ResourceCertificate resourceCertificate = createSelfSignedEeCertificateBuilder().buildResourceCertificate();
        assertTrue(resourceCertificate.isEe());
        assertFalse(resourceCertificate.isCa());

        X509ResourceCertificate cert = createSelfSignedCaResourceCertificateBuilder().buildResourceCertificate();
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
        X509ResourceCertificate cert = builder.buildResourceCertificate();
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
        X509ResourceCertificate cert = builder.buildResourceCertificate();
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
        X509ResourceCertificate cert = builder.buildResourceCertificate();
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

    @Test(expected=InvalidKeyException.class)
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

        selfSignedCert.validate(CERT_URI.toString(), context, crlLocator, result);

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
            .buildResourceCertificate();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(CERT_URI, rootCertificate);

        expect(crlLocator.getCrl(CRL_DP, context, result)).andAnswer(new IAnswer<X509Crl>() {
           @Override
        public X509Crl answer() throws Throwable {
               assertEquals(CRL_DP.toString(), result.getCurrentLocation());
               result.isTrue(false, ValidationString.CRL_SIGNATURE_VALID);
               return null;
            }
        });
        replay(crlLocator);

        result.push(CERT_URI);
        subject.validate(CERT_URI.toString(), context, crlLocator, result);

        verify(crlLocator);
        assertEquals(CERT_URI.toString(), result.getCurrentLocation());
        assertTrue("certificate should have errors", result.hasFailureForCurrentLocation());
        assertTrue("crl should have errors", result.hasFailureForLocation(CRL_DP.toString()));
    }

    @Test
    public void shouldValidateWhenCrlOk() {
        final ValidationResult result = new ValidationResult();
        X509ResourceCertificate rootCertificate = createSelfSignedCaResourceCertificate();
        X509ResourceCertificate subject = createSelfSignedCaResourceCertificateBuilder()
            .withPublicKey(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic())
            .withSubjectDN(new X500Principal("CN=child"))
            .withCrlDistributionPoints(CRL_DP)
            .buildResourceCertificate();
        X509Crl crl = X509CrlTest.createCrl();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(CERT_URI, rootCertificate);

        expect(crlLocator.getCrl(CRL_DP, context, result)).andReturn(crl);
        replay(crlLocator);

        subject.validate(CERT_URI.toString(), context, crlLocator, result);

        verify(crlLocator);
        assertEquals(CERT_URI.toString(), result.getCurrentLocation());
        assertEquals("[]", result.getFailuresForCurrentLocation().toString());
        assertFalse(result.hasFailureForLocation(CERT_URI.toString()));
    }
}
