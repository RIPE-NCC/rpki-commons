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
package net.ripe.rpki.commons.validation;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObjectFile;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.validation.objectvalidators.ResourceCertificateLocator;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateBottomUpValidator;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.CRLException;
import java.util.EnumSet;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;


public class X509ResourceCertificateBottomUpValidatorTest {

    private static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));

    private static final X500Principal FIRST_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=First Child, C=NL");
    private static final BigInteger FIRST_CHILD_SERIAL_NUMBER = ROOT_SERIAL_NUMBER.add(BigInteger.valueOf(1));
    private static final X500Principal SECOND_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=Second Child, C=NL");
    private static final BigInteger SECOND_CHILD_SERIAL_NUMBER = FIRST_CHILD_SERIAL_NUMBER.add(BigInteger.valueOf(1));
    private static final IpResourceSet CHILD_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/17, ffce::/16, AS21212");
    private static final IpResourceSet INVALID_CHILD_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/15, ffce::/16, AS21212");
    private static final ValidityPeriod EXPIRED_VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMonths(2), new DateTime().minusMonths(1));

    private static final KeyPair ROOT_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    private static final KeyPair FIRST_CHILD_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    private static final KeyPair SECOND_CHILD_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();


    private static final ValidationLocation CHILD_VALIDATION_LOCATION = new ValidationLocation("child");
    private static final ValidationLocation GRAND_CHILD_VALIDATION_LOCATION = new ValidationLocation("grandchild");

    private X509ResourceCertificate root;
    private X509ResourceCertificate child;
    private X509ResourceCertificate grandchild;

    private X509Crl rootCrl;
    private X509Crl childCrl;

    @Before
    public void setUp() {
        root = getRootResourceCertificate();
        child = createChildBuilder().build();
        grandchild = null;
        rootCrl = getRootCRL().build(ROOT_KEY_PAIR.getPrivate());
        childCrl = getChildCRL().build(FIRST_CHILD_KEY_PAIR.getPrivate());
    }


    @Test
    public void testShouldBeValidRootCertificate() {
        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("root", root);
        assertFalse(validator.getValidationResult().hasFailures());
    }

    @Test
    public void testShouldBeValidChildCertificates() throws CRLException {
        child = createChildBuilder().build();
        grandchild = createSecondChildBuilder().build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl(), root);
        validator.validate("grandchild", grandchild);
        assertFalse(validator.getValidationResult().hasFailures());
    }

    @Test
    public void testShouldFailOnInvalidResorceSet() {
        child = createChildBuilder().withInheritedResourceTypes(EnumSet.noneOf(IpResourceType.class)).withResources(INVALID_CHILD_RESOURCE_SET).build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);
        assertTrue(validator.getValidationResult().hasFailures());

        assertTrue(validator.getValidationResult().hasFailureForLocation(CHILD_VALIDATION_LOCATION));
        assertTrue(ValidationString.RESOURCE_RANGE.equals(validator.getValidationResult().getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey()));
    }

    @Test
    public void testShouldFailOnInvalidResourceSetAfterInheritance() {
        child = createChildBuilder().build();
        grandchild = createSecondChildBuilder().withResources(INVALID_CHILD_RESOURCE_SET).build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("grandchild", grandchild);
        assertTrue(validator.getValidationResult().hasFailures());

        assertTrue(validator.getValidationResult().hasFailureForLocation(GRAND_CHILD_VALIDATION_LOCATION));
        assertTrue(ValidationString.RESOURCE_RANGE.equals(validator.getValidationResult().getFailures(GRAND_CHILD_VALIDATION_LOCATION).get(0).getKey()));
    }

    @Test
    public void testShouldFailOnInvalidSignature() {
        child = createChildBuilder().withSigningKeyPair(FIRST_CHILD_KEY_PAIR).build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);
        assertTrue(validator.getValidationResult().hasFailures());
        assertTrue(validator.getValidationResult().hasFailureForLocation(CHILD_VALIDATION_LOCATION));
        assertTrue(ValidationString.SIGNATURE_VALID.equals(validator.getValidationResult().getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey()));
    }

    @Test
    public void testShouldFailOnExpiredValidityPeriod() {
        child = createChildBuilder().withValidityPeriod(EXPIRED_VALIDITY_PERIOD).build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);
        assertTrue(validator.getValidationResult().hasFailures());
        assertTrue(validator.getValidationResult().hasFailureForLocation(CHILD_VALIDATION_LOCATION));
        assertTrue(ValidationString.NOT_VALID_AFTER.equals(validator.getValidationResult().getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey()));
    }

    @Test
    public void testShouldFailOnInvalidIssuer() {
        child = createChildBuilder().withIssuerDN(SECOND_CHILD_CERTIFICATE_NAME).build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);
        assertTrue(validator.getValidationResult().hasFailures());
        assertTrue(validator.getValidationResult().hasFailureForLocation(CHILD_VALIDATION_LOCATION));
        assertTrue(ValidationString.PREV_SUBJECT_EQ_ISSUER.equals(validator.getValidationResult().getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey()));
    }

    @Test
    public void testShouldWarnOnMissingKeyUsage() {
        child = createChildBuilder().withKeyUsage(0).build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);
        assertFalse(validator.getValidationResult().hasFailures());

        assertEquals(validator.getValidationResult().getResult(CHILD_VALIDATION_LOCATION, ValidationString.KEY_USAGE_EXT_PRESENT), new ValidationCheck(ValidationStatus.WARNING, ValidationString.KEY_USAGE_EXT_PRESENT));
    }

    @Test
    public void testShouldWarnOnInvalidKeyUsage() {
        child = createChildBuilder().withKeyUsage(KeyUsage.digitalSignature).build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);
        assertFalse(validator.getValidationResult().hasFailures());

        assertEquals(validator.getValidationResult().getResult(CHILD_VALIDATION_LOCATION, ValidationString.KEY_CERT_SIGN), new ValidationCheck(ValidationStatus.WARNING, ValidationString.KEY_CERT_SIGN));
    }

    @Test
    public void testShouldFailOnMissingAKI() {
        child = createChildBuilder().withAuthorityKeyIdentifier(false).build();

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);
        assertTrue(validator.getValidationResult().hasFailures());
        assertTrue(validator.getValidationResult().hasFailureForLocation(CHILD_VALIDATION_LOCATION));
        assertTrue(ValidationString.AKI_PRESENT.equals(validator.getValidationResult().getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey()));
    }

    @Test
    public void testShouldFailOnCrlCheck() throws CRLException {
        child = createChildBuilder().build();
        grandchild = createSecondChildBuilder().build();

        rootCrl = getRootCRL().addEntry(FIRST_CHILD_SERIAL_NUMBER, VALIDITY_PERIOD.getNotValidBefore().plusDays(2)).build(ROOT_KEY_PAIR.getPrivate());
        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);

        ValidationResult validationResult = validator.getValidationResult();
        assertTrue(validationResult.hasFailures());
        assertTrue(validationResult.hasFailureForLocation(CHILD_VALIDATION_LOCATION));
        assertTrue(ValidationString.CERT_NOT_REVOKED.equals(validationResult.getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey()));
    }

    @Test
    public void testShouldFailWhenCrlInvalid() {
        child = createChildBuilder().build();
        rootCrl = getChildCRL().build(FIRST_CHILD_KEY_PAIR.getPrivate());

        X509ResourceCertificateBottomUpValidator validator = new X509ResourceCertificateBottomUpValidator(new ResourceCertificateLocatorImpl());
        validator.validate("child", child);

        ValidationResult validationResult = validator.getValidationResult();
        assertTrue(validationResult.hasFailures());
        assertTrue(ValidationString.CRL_SIGNATURE_VALID.equals(validationResult.getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey()));
    }

    private X509ResourceCertificate getRootResourceCertificate() {
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
        return builder.build();
    }

    private X509ResourceCertificateBuilder createChildBuilder() {
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
        builder.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));
        builder.withValidityPeriod(VALIDITY_PERIOD);
        builder.withCrlDistributionPoints(URI.create("rsync://localhost/ta.crl"));
        return builder;
    }

    private X509ResourceCertificateBuilder createSecondChildBuilder() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

        builder.withSubjectDN(SECOND_CHILD_CERTIFICATE_NAME);
        builder.withIssuerDN(FIRST_CHILD_CERTIFICATE_NAME);
        builder.withSerial(SECOND_CHILD_SERIAL_NUMBER);
        builder.withPublicKey(SECOND_CHILD_KEY_PAIR.getPublic());
        builder.withAuthorityKeyIdentifier(true);
        builder.withSigningKeyPair(FIRST_CHILD_KEY_PAIR);
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withValidityPeriod(VALIDITY_PERIOD);
        builder.withAuthorityKeyIdentifier(true);
        builder.withSubjectKeyIdentifier(true);
        builder.withResources(CHILD_RESOURCE_SET);
        builder.withCrlDistributionPoints(URI.create("rsync://localhost/prod.crl"));
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

    private X509CrlBuilder getChildCRL() {
        X509CrlBuilder builder = new X509CrlBuilder();

        builder.withIssuerDN(FIRST_CHILD_CERTIFICATE_NAME);
        builder.withThisUpdateTime(VALIDITY_PERIOD.getNotValidBefore().plusDays(1));
        builder.withNextUpdateTime(new DateTime().plusMonths(1));
        builder.withNumber(BigInteger.valueOf(1));
        builder.withAuthorityKeyIdentifier(FIRST_CHILD_KEY_PAIR.getPublic());
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }


    private class ResourceCertificateLocatorImpl implements ResourceCertificateLocator {

        @Override
        public CertificateRepositoryObjectFile<X509ResourceCertificate> findParent(X509ResourceCertificate certificate) {
            Validate.isTrue(!certificate.isRoot());
            if (certificate.equals(grandchild)) {
                return new CertificateRepositoryObjectFile<X509ResourceCertificate>(X509ResourceCertificate.class, "child", child.getEncoded());
            } else if (certificate.equals(child)) {
                return new CertificateRepositoryObjectFile<X509ResourceCertificate>(X509ResourceCertificate.class, "root", root.getEncoded());
            } else {
                throw new IllegalArgumentException("unable to find parent for certificate: " + certificate);
            }
        }

        @Override
        public CertificateRepositoryObjectFile<X509Crl> findCrl(X509ResourceCertificate certificate) {

            if (certificate.equals(child)) {
                return new CertificateRepositoryObjectFile<X509Crl>(X509Crl.class, "rootCrl", rootCrl.getEncoded());
            }

            if (certificate.equals(grandchild)) {
                return new CertificateRepositoryObjectFile<X509Crl>(X509Crl.class, "childCrl", childCrl.getEncoded());
            }

            return null;
        }
    }
}
