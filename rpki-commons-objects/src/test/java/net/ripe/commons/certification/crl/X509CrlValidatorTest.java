package net.ripe.commons.certification.crl;

import static net.ripe.commons.certification.util.KeyPairFactoryTest.*;
import static net.ripe.commons.certification.validation.ValidationString.*;
import static net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.crl.X509CrlValidator;
import net.ripe.commons.certification.util.KeyPairFactory;
import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

public class X509CrlValidatorTest {


    // Test data
    private static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));

    private static final KeyPair ROOT_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);
    private static final KeyPair FIRST_CHILD_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

    private X509CrlValidator subject;
    private X509ResourceCertificate parent;
    private ValidationResult result;


    @Before
    public void setUp() {
        parent = getRootResourceCertificate();
        result = new ValidationResult();
        subject = new X509CrlValidator(result, parent);
    }

    @Test
    public void shouldValidateHappyflowCrl() {
        X509Crl crl = getRootCRL().build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertFalse(result.hasFailures());
        assertEquals("location", result.getCurrentLocation());
    }

    @Test
    public void shouldRejectCrlSignedByOthers() {
        X509Crl crl = getRootCRL().build(FIRST_CHILD_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertTrue(result.hasFailures());
        assertEquals(new ValidationCheck(false, CRL_SIGNATURE_VALID), result.getResult("location", CRL_SIGNATURE_VALID));
    }

    @Test
    public void shouldRejectWhenNextUpdatePassed() {
        DateTime nextUpdateTime = new DateTime(DateTimeZone.UTC).minusSeconds(1).withMillisOfSecond(0);
        X509Crl crl = getRootCRL().withNextUpdateTime(nextUpdateTime).build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertTrue(result.hasFailures());
        assertEquals(new ValidationCheck(false, CRL_NEXT_UPDATE_BEFORE_NOW, nextUpdateTime), result.getResult("location", CRL_NEXT_UPDATE_BEFORE_NOW));
    }


    private X509ResourceCertificate getRootResourceCertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

        builder.withSubjectDN(ROOT_CERTIFICATE_NAME);
        builder.withIssuerDN(ROOT_CERTIFICATE_NAME);
        builder.withSerial(ROOT_SERIAL_NUMBER);
        builder.withValidityPeriod(VALIDITY_PERIOD);
        builder.withPublicKey(ROOT_KEY_PAIR.getPublic());
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign);
        builder.withAuthorityKeyIdentifier(true);
        builder.withSubjectKeyIdentifier(true);
        builder.withResources(ROOT_RESOURCE_SET);
        builder.withAuthorityKeyIdentifier(false);
        builder.withSigningKeyPair(ROOT_KEY_PAIR);
        return builder.build();
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
