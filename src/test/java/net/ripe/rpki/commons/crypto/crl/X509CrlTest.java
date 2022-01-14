package net.ripe.rpki.commons.crypto.crl;

import net.ripe.rpki.commons.crypto.util.KeyPairUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.joda.time.DateTime;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class X509CrlTest {

    private static final URI ROOT_MANIFEST_CRL_LOCATION = URI.create("rsync://foo.host/bar/bar%20space.crl");

    private static final ValidationOptions VALIDATION_OPTIONS = ValidationOptions.strictValidation();


    public static X509Crl createCrl() {
        X509CrlBuilder builder = getCrlBuilder();
        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

    public static X509CrlBuilder getCrlBuilder() {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(new X500Principal("CN=issuer"));
        final DateTime now = UTC.dateTime();
        builder.withThisUpdateTime(now);
        builder.withNextUpdateTime(now.plusHours(8));
        builder.withNumber(BigInteger.TEN);
        builder.withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic());
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }

    private X509Crl getCrlWithKeyPair(KeyPair keyPair) {
        X509CrlBuilder builder = getCrlBuilder();
        builder.withAuthorityKeyIdentifier(keyPair.getPublic());
        return builder.build(keyPair.getPrivate());
    }

    @Test
    public void shouldHaveAuthorityKeyIdentifier() {
        X509Crl crl = createCrl();
        assertArrayEquals(KeyPairUtil.getKeyIdentifier(TEST_KEY_PAIR.getPublic()), crl.getAuthorityKeyIdentifier());
    }


    @Test
    public void shouldValidateCrl() {
        X509Crl subject = createCrl();
        ValidationResult result = ValidationResult.withLocation(ROOT_MANIFEST_CRL_LOCATION);
        CrlLocator crlLocator = mock(CrlLocator.class);

        X509ResourceCertificate selfSignedCaResourceCertificate = createSelfSignedCaResourceCertificate();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_MANIFEST_CRL_LOCATION, selfSignedCaResourceCertificate);

        subject.validate(ROOT_MANIFEST_CRL_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldNotValidateInvalidCrl() {
        X509Crl subject = getCrlWithKeyPair(SECOND_TEST_KEY_PAIR);
        ValidationResult result = ValidationResult.withLocation(ROOT_MANIFEST_CRL_LOCATION);
        CrlLocator crlLocator = mock(CrlLocator.class);

        X509ResourceCertificate selfSignedCaResourceCertificate = createSelfSignedCaResourceCertificate();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_MANIFEST_CRL_LOCATION, selfSignedCaResourceCertificate);

        subject.validate(ROOT_MANIFEST_CRL_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertTrue(result.hasFailures());
        assertTrue(result.getValidatedLocations().size() == 1);
        ValidationLocation rootMftCrlValidationLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);
        assertTrue(result.hasFailureForLocation(rootMftCrlValidationLocation));
        assertEquals(ValidationString.CRL_SIGNATURE_VALID, result.getFailures(rootMftCrlValidationLocation).get(0).getKey());
    }

    @Test
    public void shouldBePastValidityTime() {
        X509Crl subject = createCrl();
        assertFalse(subject.isPastValidityTime());
    }
}
