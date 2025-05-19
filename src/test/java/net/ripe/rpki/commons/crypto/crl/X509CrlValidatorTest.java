package net.ripe.rpki.commons.crypto.crl;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;

public class X509CrlValidatorTest {

    // Test data
    private static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final ValidityPeriod VALIDITY_PERIOD;

    static {
        final DateTime now = UTC.dateTime();
        VALIDITY_PERIOD = new ValidityPeriod(now.minusDays(2), now.plusDays(2));
    }

    private static final KeyPair ROOT_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    private static final KeyPair FIRST_CHILD_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    private X509CrlValidator subject;
    private X509ResourceCertificate parent;

    private ValidationOptions options;
    private ValidationResult result;


    @Before
    public void setUp() {
        parent = getRootResourceCertificate();
        options = ValidationOptions.backCompatibleRipeNccValidator();
        result = ValidationResult.withLocation("location");
        subject = new X509CrlValidator(options, result, parent);
    }

    @Test
    public void shouldValidateHappyflowCrl() {
        X509Crl crl = getRootCRL().build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertFalse(result.hasFailures());
        assertEquals(new ValidationLocation("location"), result.getCurrentLocation());
    }

    @Test
    public void shouldRejectCrlSignedByOthers() {
        X509Crl crl = getRootCRL().build(FIRST_CHILD_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertTrue(result.hasFailures());
        assertEquals(new ValidationCheck(ValidationStatus.ERROR, CRL_SIGNATURE_VALID), result.getResult(new ValidationLocation("location"), CRL_SIGNATURE_VALID));
    }

    @Test
    public void shouldRejectWhenThisUpdateInFuture() {
        DateTime now = UTC.dateTime().withMillisOfSecond(0);
        DateTime thisUpdateTime = now.plusDays(2);
        DateTime nextUpdateTime = now.plusDays(4);
        X509Crl crl = getRootCRL().withValidityPeriod(new ValidityPeriod(thisUpdateTime, nextUpdateTime)).build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertTrue(result.hasFailures());
        assertEquals(new ValidationCheck(ValidationStatus.ERROR, CRL_THIS_UPDATE_AFTER_NOW, thisUpdateTime.toString()), result.getResult(new ValidationLocation("location"), CRL_THIS_UPDATE_AFTER_NOW));
    }

    @Test
    public void shouldWarnWhenNextUpdatePassedWithinMaxStaleDays() {
        options = ValidationOptions.withStaleConfigurations(Duration.standardDays(1), Duration.ZERO);

        // Just update next update
        var newValidity = new ValidityPeriod(getRootCRL().getThisUpdateTime(), UTC.dateTime().minusSeconds(1).withMillisOfSecond(0));
        X509Crl crl = getRootCRL().withValidityPeriod(newValidity).build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertFalse(result.hasFailures());
        assertEquals(new ValidationCheck(ValidationStatus.WARNING, CRL_NEXT_UPDATE_BEFORE_NOW, newValidity.getNotValidAfter().toString()), result.getResult(new ValidationLocation("location"), CRL_NEXT_UPDATE_BEFORE_NOW));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldRejectWhenNextUpdateOutsideMaxStaleDays() {
        options = ValidationOptions.withStaleConfigurations(Duration.standardDays(1), Duration.ZERO);
        subject = new X509CrlValidator(options, result, parent);
        // validity period checks this invariant -> explicitly set nextUpdateTime
        DateTime nextUpdateTime = UTC.dateTime().minusDays(2).withMillisOfSecond(0); // Truncate millis
        X509Crl crl = getRootCRL().withNextUpdateTime(nextUpdateTime).build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertTrue(result.hasFailures());
        assertEquals(new ValidationCheck(ValidationStatus.ERROR, CRL_NEXT_UPDATE_BEFORE_NOW, nextUpdateTime.toString()), result.getResult(new ValidationLocation("location"), CRL_NEXT_UPDATE_BEFORE_NOW));
    }

    @Test
    public void shouldRejectWhenNextUpdateOutsideNegativeMaxStaleDays() {
        options = ValidationOptions.withStaleConfigurations(Duration.standardDays(-8), Duration.ZERO);
        subject = new X509CrlValidator(options, result, parent);
        var newValidity = new ValidityPeriod(getRootCRL().getThisUpdateTime(), UTC.dateTime().withMillisOfSecond(0)); // Truncate millis
        X509Crl crl = getRootCRL().withValidityPeriod(newValidity).build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertTrue(result.hasFailures());
        assertEquals(new ValidationCheck(ValidationStatus.ERROR, CRL_NEXT_UPDATE_BEFORE_NOW, newValidity.getNotValidAfter().toString()), result.getResult(new ValidationLocation("location"), CRL_NEXT_UPDATE_BEFORE_NOW));
    }

    @Test
    public void shouldNotRejectWhenBetweenThisUpdateAndNextUpdate() {
        DateTime thisUpdateTime = UTC.dateTime().minusDays(1);
        DateTime nextUpdateTime = thisUpdateTime.plusDays(2);
        var validity = new ValidityPeriod(thisUpdateTime, nextUpdateTime);
        X509Crl crl = getRootCRL().withValidityPeriod(validity).build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertFalse(result.hasFailures());
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
        builder.withResources(ROOT_RESOURCE_SET);
        builder.withAuthorityKeyIdentifier(false);
        builder.withSigningKeyPair(ROOT_KEY_PAIR);
        return builder.build();
    }

    private X509CrlBuilder getRootCRL() {
        X509CrlBuilder builder = new X509CrlBuilder();

        builder.withIssuerDN(ROOT_CERTIFICATE_NAME);
        builder.withValidityPeriod(new ValidityPeriod(VALIDITY_PERIOD.getNotValidBefore().plusDays(1), UTC.dateTime().plusMonths(1)));
        builder.withNumber(BigInteger.valueOf(1));
        builder.withAuthorityKeyIdentifier(ROOT_KEY_PAIR.getPublic());
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }
}
