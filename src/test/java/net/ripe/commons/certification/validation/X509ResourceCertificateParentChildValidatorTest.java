package net.ripe.commons.certification.validation;

import static net.ripe.commons.certification.util.KeyPairFactoryTest.*;
import static net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.util.KeyPairFactory;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateParentChildValidator;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;


public class X509ResourceCertificateParentChildValidatorTest {

	private static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
	private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
	private static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
	private static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));

	private static final X500Principal FIRST_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=First Child, C=NL");
	private static final BigInteger FIRST_CHILD_SERIAL_NUMBER = ROOT_SERIAL_NUMBER.add(BigInteger.valueOf(1));
	private static final X500Principal SECOND_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=Second Child, C=NL");
	private static final IpResourceSet INVALID_CHILD_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/15, ffce::/16, AS21212");
    private static final ValidityPeriod EXPIRED_VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMonths(2), new DateTime().minusMonths(1));

	private static final KeyPair ROOT_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);
	private static final KeyPair FIRST_CHILD_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);
	private static final KeyPair SECOND_CHILD_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);


	private X509ResourceCertificate root;
	private X509ResourceCertificate child;

	private X509Crl rootCrl;

	private ValidationResult result;

	@Before
	public void setUp() {
        root = getRootResourceCertificate();
        child = createChildCertificateBuilder().build();
        rootCrl = getRootCRL().build(ROOT_KEY_PAIR.getPrivate());
        result = new ValidationResult();
	}

	private void validate(X509ResourceCertificateParentChildValidator validator, X509ResourceCertificate certificate) {
		String location = "child";
		validator.validate(location, certificate);
	}

	@Test
	public void shouldAcceptHappyFlowChildCertificate() {
		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());

		validate(validator, child);

		assertFalse(result.hasFailures());
	}

	@Test
	public void shouldRejectInvalidSignature() {
		child = createChildCertificateBuilder().withSigningKeyPair(SECOND_CHILD_KEY_PAIR).build();

		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
		validate(validator, child);

		assertTrue(result.hasFailures());
    	assertTrue(result.hasFailureForLocation("child"));
    	assertTrue(ValidationString.SIGNATURE_VALID.equals(result.getFailures("child").get(0).getKey()));
	}

	@Test
	public void shouldAcceptSelfSignedSignature() {
		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());

		validate(validator, root);

		assertFalse(result.hasFailures());
	}

	@Test
	public void shouldRejectRevokedCertificate() {
		rootCrl = getRootCRL().addEntry(FIRST_CHILD_SERIAL_NUMBER, VALIDITY_PERIOD.getNotValidBefore().plusDays(2)).build(ROOT_KEY_PAIR.getPrivate());

		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
		validate(validator, child);

		assertTrue(result.hasFailures());
    	assertTrue(ValidationString.CERT_NOT_REVOKED.equals(result.getFailures("child").get(0).getKey()));
	}

	@Test
	public void shouldRejectIfCrlAbsentForNonRootCertificate() {
		rootCrl = null;

		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
		validate(validator, child);

		assertTrue(result.hasFailures());
	}

	@Test
	public void shouldRejectCertificateWithWrongValidity() {
		child = createChildCertificateBuilder().withValidityPeriod(EXPIRED_VALIDITY_PERIOD).build();

		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
		validate(validator, child);

		assertTrue(result.hasFailures());
    	assertTrue(ValidationString.NOT_VALID_AFTER.equals(result.getFailures("child").get(0).getKey()));

	}

	@Test
	public void shouldRejectInvalidIssuer() {
		child = createChildCertificateBuilder().withIssuerDN(SECOND_CHILD_CERTIFICATE_NAME).build();

		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
		validate(validator, child);

		assertTrue(result.hasFailures());
    	assertTrue(ValidationString.PREV_SUBJECT_EQ_ISSUER.equals(result.getFailures("child").get(0).getKey()));

	}

	@Test
	public void shouldRejectInvalidKeyUsage() {
		child = createChildCertificateBuilder().withKeyUsage(KeyUsage.digitalSignature).build();

		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
		validate(validator, child);

		assertTrue(result.hasFailures());
		assertTrue(ValidationString.KEY_CERT_SIGN.equals(result.getFailures("child").get(0).getKey()));
	}

    @Test
    public void shouldRejectOnMisingKeyUsage() {
		child = createChildCertificateBuilder().withKeyUsage(0).build();

		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
		validate(validator, child);

		assertTrue(result.hasFailures());
		assertTrue(ValidationString.KEY_USAGE_EXT_PRESENT.equals(result.getFailures("child").get(0).getKey()));
    }

    @Test
    public void shouldRejectMissingAuthorityKeyIdentifier() {
    	child = createChildCertificateBuilder().withAuthorityKeyIdentifier(false).build();

    	X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
    	validate(validator, child);

		assertTrue(result.hasFailures());
		assertTrue(ValidationString.AKI_PRESENT.equals(result.getFailures("child").get(0).getKey()));
    }

    @Test
    public void shouldRejectInvalidResorceSet() {
		child = createChildCertificateBuilder().withResources(INVALID_CHILD_RESOURCE_SET).build();

		X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
		validate(validator, child);

		assertTrue(result.hasFailures());
    }

    @Test
    public void shouldRejectInheritedResourcesForSelfSignedCertificate() {
    	root = getRootResourceCertificateWithInheritedResources();
    	child = getRootResourceCertificateWithInheritedResources();

    	X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, root, rootCrl, root.getResources());
    	validate(validator, child);

    	assertTrue(result.hasFailures());
    }


    private X509ResourceCertificate getRootResourceCertificate() {
        return createRootCertificateBuilder().build();
    }

    private X509ResourceCertificate getRootResourceCertificateWithInheritedResources() {
    	return createRootCertificateBuilder().withResources(InheritedIpResourceSet.getInstance()).build();
    }

    private X509ResourceCertificateBuilder createRootCertificateBuilder() {
    	X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

    	builder.withSubjectDN(ROOT_CERTIFICATE_NAME);
        builder.withIssuerDN(ROOT_CERTIFICATE_NAME);
        builder.withSerial(ROOT_SERIAL_NUMBER);
        builder.withValidityPeriod(VALIDITY_PERIOD);
        builder.withPublicKey(ROOT_KEY_PAIR.getPublic());
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withAuthorityKeyIdentifier(true);
        builder.withSubjectKeyIdentifier(true);
        builder.withResources(ROOT_RESOURCE_SET);
        builder.withAuthorityKeyIdentifier(false);
        builder.withSigningKeyPair(ROOT_KEY_PAIR);

        return builder;
    }

	private X509ResourceCertificateBuilder createChildCertificateBuilder() {
		X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

    	builder.withSubjectDN(FIRST_CHILD_CERTIFICATE_NAME);
        builder.withIssuerDN(ROOT_CERTIFICATE_NAME);
        builder.withSerial(FIRST_CHILD_SERIAL_NUMBER);
        builder.withPublicKey(FIRST_CHILD_KEY_PAIR.getPublic());
        builder.withAuthorityKeyIdentifier(true);
        builder.withSigningKeyPair(ROOT_KEY_PAIR);
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withAuthorityKeyIdentifier(true);
        builder.withSubjectKeyIdentifier(true);
        builder.withResources(InheritedIpResourceSet.getInstance());
        builder.withValidityPeriod(VALIDITY_PERIOD);
		return builder;
	}


	private X509CrlBuilder getRootCRL() {
    	X509CrlBuilder builder = new X509CrlBuilder();

    	builder.withIssuerDN(ROOT_CERTIFICATE_NAME);
    	builder.withThisUpdateTime(VALIDITY_PERIOD.getNotValidBefore().plusDays(1));
    	builder.withNextUpdateTime(new DateTime().plusMonths(1));
    	builder.withNumber(BigInteger.valueOf(1));
    	builder.withAuthorityKeyIdentifier(ROOT_KEY_PAIR.getPublic());
    	builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }

}
