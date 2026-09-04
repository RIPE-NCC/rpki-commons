package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlTest;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SignatureException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


public class X509RouterCertificateTest {

    public static final X500Principal TEST_SELF_SIGNED_CERTIFICATE_NAME = new X500Principal("CN=TEST-SELF-SIGNED-CERT");

    private static final ValidityPeriod TEST_VALIDITY_PERIOD;

    static {
        final DateTime now = UTC.dateTime();
        TEST_VALIDITY_PERIOD = new ValidityPeriod(now.minusMinutes(1), now.plusYears(100));
    }

    private static final BigInteger TEST_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final URI TEST_CERTIFICATE_URI = URI.create("rsync://host.foo/router.cer");
    private static final URI TEST_CRL_URI = URI.create("rsync://host.foo/router.crl");
    private static final ValidationOptions VALIDATION_OPTIONS = ValidationOptions.strictValidation();

    public static X509RouterCertificateBuilder createBasicBuilder() {
        X509RouterCertificateBuilder builder = new X509RouterCertificateBuilder();
        builder.withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withSerial(TEST_SERIAL_NUMBER);
        builder.withValidityPeriod(TEST_VALIDITY_PERIOD);
        builder.withPublicKey(KeyPairFactoryTest.TEST_EC_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        builder.withAuthorityKeyIdentifier(true);
        builder.withAsns(new int[] {1, 22, 333});
        return builder;
    }

    public static X509RouterCertificateBuilder createSelfSignedRouterCertificateBuilder() {
        return createBasicBuilder().withCa(false)
                .withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME)
                .withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
    }

    @Test(expected = NullPointerException.class)
    public void shouldRequireCertificate() {
        new X509RouterCertificate(null);
    }

    @Test
    public void shouldSupportCaCertificate() {
        X509RouterCertificate cert = createSelfSignedRouterCertificateBuilder().build();
        assertFalse(cert.isCa());
        assertTrue(cert.isRouter());
    }

    @Test
    public void shouldSupportAuthorityInformationAccessExtension() throws URISyntaxException {
        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, new URI("rsync://foo.host/bar/baz.cer")),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, new URI("http://foo.host/bar/baz.cer"))
        };
        X509RouterCertificateBuilder builder = createSelfSignedRouterCertificateBuilder();
        builder.withAuthorityInformationAccess(descriptors);
        X509RouterCertificate cert = builder.build();
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
        X509RouterCertificateBuilder builder = createSelfSignedRouterCertificateBuilder();
        builder.withSubjectInformationAccess(descriptors);
        X509RouterCertificate cert = builder.build();
        assertArrayEquals(descriptors, cert.getSubjectInformationAccess());
        assertNotNull(cert.findFirstSubjectInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY));
    }

    @Test
    public void shouldSupportCrlDistributionPoints() {
        URI[] crlDistributionPoints = {
                URI.create("rsync://localhost/ca.crl")
        };
        X509RouterCertificateBuilder builder = createSelfSignedRouterCertificateBuilder();
        builder.withCrlDistributionPoints(crlDistributionPoints);
        X509RouterCertificate cert = builder.build();
        assertArrayEquals(crlDistributionPoints, cert.getCrlDistributionPoints());
        assertNotNull(cert.findFirstRsyncCrlDistributionPoint());
    }

    @Test
    public void shouldHaveValidSignature() throws Exception {
        X509RouterCertificate certificate = createSelfSignedRouterCertificateBuilder().build();
        certificate.getCertificate().verify(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
    }

    @Test(expected = SignatureException.class)
    public void shouldFailOnInvalidSignature() throws Exception {
        X509RouterCertificate certificate = createSelfSignedRouterCertificateBuilder().build();
        certificate.getCertificate().verify(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic());
    }

    @Test
    public void shouldValidateWithLocatedCrl() {
        X509RouterCertificate subject = createChildRouterCertificate();
        X509RouterCertificate parent = createValidationParent(subject.getIssuer(), subject.getAuthorityKeyIdentifier());
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(TEST_CERTIFICATE_URI, parent);
        ValidationResult result = ValidationResult.withLocation(TEST_CERTIFICATE_URI);
        CrlLocator crlLocator = mock(CrlLocator.class);

        when(crlLocator.getCrl(TEST_CRL_URI, context, result)).thenAnswer(invocation -> {
            assertEquals(new ValidationLocation(TEST_CERTIFICATE_URI), result.getCurrentLocation());
            return X509CrlTest.createCrl();
        });

        subject.validate(TEST_CERTIFICATE_URI.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertFalse(result.hasFailures());
        assertFalse(subject.isRevoked());
        verify(crlLocator).getCrl(TEST_CRL_URI, context, result);
    }

    @Test
    public void shouldFailValidationWhenLocatedCrlIsMissing() {
        X509RouterCertificate subject = createChildRouterCertificate();
        X509RouterCertificate parent = createValidationParent(subject.getIssuer(), subject.getAuthorityKeyIdentifier());
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(TEST_CERTIFICATE_URI, parent);
        ValidationResult result = ValidationResult.withLocation(TEST_CERTIFICATE_URI);
        CrlLocator crlLocator = mock(CrlLocator.class);

        when(crlLocator.getCrl(TEST_CRL_URI, context, result)).thenReturn(null);

        subject.validate(TEST_CERTIFICATE_URI.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertTrue(result.hasFailureForCurrentLocation());
        assertEquals(ValidationString.OBJECTS_CRL_VALID, result.getFailures(new ValidationLocation(TEST_CERTIFICATE_URI)).get(0).getKey());
    }

    @Test
    public void shouldFailExplicitValidationWhenCrlIsMissingForNonRootCertificate() {
        X509RouterCertificate subject = createChildRouterCertificate();
        X509RouterCertificate parent = createValidationParent(subject.getIssuer(), subject.getAuthorityKeyIdentifier());
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(TEST_CERTIFICATE_URI, parent);
        ValidationResult result = ValidationResult.withLocation(TEST_CERTIFICATE_URI);

        subject.validate(TEST_CERTIFICATE_URI.toString(), context, null, TEST_CRL_URI, VALIDATION_OPTIONS, result, certificate -> false);

        assertTrue(result.hasFailureForCurrentLocation());
        assertEquals(ValidationString.OBJECTS_CRL_VALID, result.getFailures(new ValidationLocation(TEST_CERTIFICATE_URI)).get(0).getKey());
    }

    @Test
    public void shouldMarkCertificateAsRevokedWhenExplicitCrlContainsRouterCertificate() {
        X509RouterCertificate subject = createChildRouterCertificate();
        X509RouterCertificate parent = createValidationParent(subject.getIssuer(), subject.getAuthorityKeyIdentifier());
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(TEST_CERTIFICATE_URI, parent);
        ValidationResult result = ValidationResult.withLocation(TEST_CERTIFICATE_URI);
        X509Crl crl = X509CrlTest.getCrlBuilder()
                .withIssuerDN(subject.getIssuer())
                .addEntry(subject.getSerialNumber(), UTC.dateTime().minusDays(1))
                .build(KeyPairFactoryTest.TEST_KEY_PAIR.getPrivate());

        subject.validate(TEST_CERTIFICATE_URI.toString(), context, crl, TEST_CRL_URI, VALIDATION_OPTIONS, result, certificate -> false);

        assertTrue(subject.isRevoked());
    }

    private static X509RouterCertificate createChildRouterCertificate() {
        return createSelfSignedRouterCertificateBuilder()
                .withSubjectDN(new X500Principal("CN=router-child"))
                .withIssuerDN(new X500Principal("CN=router-parent"))
                .withSerial(TEST_SERIAL_NUMBER.add(BigInteger.ONE))
                .withKeyUsage(KeyUsage.digitalSignature)
                .withCrlDistributionPoints(TEST_CRL_URI)
                .build();
    }

    private static X509RouterCertificate createValidationParent(X500Principal subject, byte[] subjectKeyIdentifier) {
        X509RouterCertificate parent = mock(X509RouterCertificate.class);
        when(parent.isCa()).thenReturn(true);
        when(parent.getPublicKey()).thenReturn(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
        when(parent.getSubject()).thenReturn(subject);
        when(parent.getSubjectKeyIdentifier()).thenReturn(subjectKeyIdentifier);
        when(parent.getResources()).thenReturn(IpResourceSet.parse("AS1"));
        return parent;
    }

}
