package net.ripe.commons.certification.crl;

import static net.ripe.commons.certification.util.KeyPairFactoryTest.*;
import static net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder.*;
import static net.ripe.commons.certification.x509cert.X509ResourceCertificateTest.*;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.util.KeyPairUtil;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import org.joda.time.DateTime;
import org.junit.Test;

public class X509CrlTest {

	private static final URI ROOT_MANIFEST_CRL_LOCATION = URI.create("rsync://foo.host/bar/bar%20space.crl");


    public static X509Crl createCrl() {
        X509CrlBuilder builder = getCrlBuilder();
        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

	public static X509CrlBuilder getCrlBuilder() {
		X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(new X500Principal("CN=issuer"));
        builder.withThisUpdateTime(new DateTime());
        builder.withNextUpdateTime(new DateTime().plusHours(8));
        builder.withNumber(BigInteger.TEN);
        builder.withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic());
        builder.addEntry(BigInteger.TEN, new DateTime().minusDays(1));
        builder.addEntry(BigInteger.valueOf(42), new DateTime().minusDays(3));
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
    	ValidationResult result = new ValidationResult();
    	CrlLocator crlLocator = createMock(CrlLocator.class);

    	CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_MANIFEST_CRL_LOCATION, createSelfSignedCaResourceCertificate());

    	replay(crlLocator);

    	subject.validate(ROOT_MANIFEST_CRL_LOCATION.toString(), context, crlLocator, result);

    	verify(crlLocator);

    	assertFalse(result.hasFailures());
    }

    @Test
    public void shouldNotValidateInvalidCrl() {
    	X509Crl subject = getCrlWithKeyPair(SECOND_TEST_KEY_PAIR);
    	ValidationResult result = new ValidationResult();
    	CrlLocator crlLocator = createMock(CrlLocator.class);

    	CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_MANIFEST_CRL_LOCATION, createSelfSignedCaResourceCertificate());

    	replay(crlLocator);

    	subject.validate(ROOT_MANIFEST_CRL_LOCATION.toString(), context, crlLocator, result);

    	verify(crlLocator);

    	assertTrue(result.hasFailures());
    	assertTrue(result.getValidatedLocations().size() ==1);
    	assertTrue(result.hasFailureForLocation(ROOT_MANIFEST_CRL_LOCATION.toString()));
    	assertEquals(ValidationString.CRL_SIGNATURE_VALID, result.getFailures(ROOT_MANIFEST_CRL_LOCATION.toString()).get(0).getKey());
    }
}
