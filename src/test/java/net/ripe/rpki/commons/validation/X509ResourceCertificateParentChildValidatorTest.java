/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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

import com.pholser.junit.quickcheck.From;
import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateParentChildLooseValidator;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateParentChildValidator;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateValidator;
import net.ripe.rpki.commons.validation.properties.IpResourceGen;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.EnumSet;
import java.util.List;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitQuickcheck.class)
public class X509ResourceCertificateParentChildValidatorTest {

    private static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final DateTime NOW = UTC.dateTime();
    private static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(NOW.minusMinutes(1), NOW.plusYears(1));

    private static final X500Principal FIRST_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=First Child, C=NL");
    private static final BigInteger FIRST_CHILD_SERIAL_NUMBER = ROOT_SERIAL_NUMBER.add(BigInteger.valueOf(1));
    private static final X500Principal SECOND_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=Second Child, C=NL");
    private static final IpResourceSet INVALID_CHILD_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/15, ffce::/16, AS21212");
    private static final ValidityPeriod EXPIRED_VALIDITY_PERIOD = new ValidityPeriod(NOW.minusMonths(2), NOW.minusMonths(1));

    private static final KeyPair ROOT_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    private static final KeyPair FIRST_CHILD_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    private static final KeyPair SECOND_CHILD_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    private static final ValidationLocation CHILD_VALIDATION_LOCATION = new ValidationLocation("child");

    private X509ResourceCertificate root;
    private X509ResourceCertificate child;

    private X509Crl rootCrl;

    private ValidationResult result;

    private ValidationOptions options;

    @Before
    public void setUp() {
        root = getRootResourceCertificate();
        child = createChildCertificateBuilder().build();
        rootCrl = getRootCRL().build(ROOT_KEY_PAIR.getPrivate());
        result = ValidationResult.withLocation("n/a");
        options = ValidationOptions.strictValidation();
    }

    private void validate(X509ResourceCertificateParentChildValidator validator, X509ResourceCertificate certificate) {
        String location = "child";
        validator.validate(location, certificate);
    }

    @Test
    public void shouldAcceptHappyFlowChildCertificate() {
        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());

        validate(validator, child);

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldRejectInvalidSignature() {
        child = createChildCertificateBuilder().withSigningKeyPair(SECOND_CHILD_KEY_PAIR).build();

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertTrue(result.hasFailures());
        assertTrue(result.hasFailureForLocation(CHILD_VALIDATION_LOCATION));
        assertEquals(ValidationString.SIGNATURE_VALID, result.getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey());
    }

    @Test
    public void shouldAcceptSelfSignedSignature() {
        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());

        validate(validator, root);

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldRejectRevokedCertificate() {
        rootCrl = getRootCRL().addEntry(FIRST_CHILD_SERIAL_NUMBER, VALIDITY_PERIOD.getNotValidBefore().plusDays(2)).build(ROOT_KEY_PAIR.getPrivate());

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertTrue(result.hasFailures());
        assertEquals(ValidationString.CERT_NOT_REVOKED, result.getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey());
    }

    @Test
    public void shouldRejectIfCrlAbsentForNonRootCertificate() {
        rootCrl = null;

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertTrue(result.hasFailures());
    }

    @Test
    public void shouldRejectCertificateWithWrongValidity() {
        child = createChildCertificateBuilder().withValidityPeriod(EXPIRED_VALIDITY_PERIOD).build();

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertTrue(result.hasFailures());
        assertEquals(ValidationString.NOT_VALID_AFTER, result.getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey());

    }

    @Test
    public void shouldRejectInvalidIssuer() {
        child = createChildCertificateBuilder().withIssuerDN(SECOND_CHILD_CERTIFICATE_NAME).build();

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertTrue(result.hasFailures());
        assertEquals(ValidationString.PREV_SUBJECT_EQ_ISSUER, result.getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey());
    }

    @Test
    public void shouldWarnOnInvalidKeyUsage() {
        child = createChildCertificateBuilder().withKeyUsage(KeyUsage.digitalSignature).build();

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertFalse(result.hasFailures());
        assertEquals(result.getResult(CHILD_VALIDATION_LOCATION, ValidationString.KEY_CERT_SIGN), new ValidationCheck(ValidationStatus.WARNING, ValidationString.KEY_CERT_SIGN));
    }

    @Test
    public void shouldWarnOnMissingKeyUsage() {
        child = createChildCertificateBuilder().withKeyUsage(0).build();

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertFalse(result.hasFailures());
        assertEquals(result.getResult(CHILD_VALIDATION_LOCATION, ValidationString.KEY_USAGE_EXT_PRESENT), new ValidationCheck(ValidationStatus.WARNING, ValidationString.KEY_USAGE_EXT_PRESENT));
    }

    @Test
    public void shouldRejectMissingAuthorityKeyIdentifier() {
        child = createChildCertificateBuilder().withAuthorityKeyIdentifier(false).build();

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertTrue(result.hasFailures());
        assertEquals(ValidationString.AKI_PRESENT, result.getFailures(CHILD_VALIDATION_LOCATION).get(0).getKey());
    }

    @Test
    public void shouldRejectInvalidResourceSet() {
        child = createChildCertificateBuilder().withInheritedResourceTypes(EnumSet.noneOf(IpResourceType.class)).withResources(INVALID_CHILD_RESOURCE_SET).build();

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertTrue(result.hasFailures());
    }

    @Test
    public void shouldRejectInheritedResourcesForSelfSignedCertificate() {
        root = getRootResourceCertificateWithInheritedResources();
        child = getRootResourceCertificateWithInheritedResources();

        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(options, result, root, rootCrl, root.getResources());
        validate(validator, child);

        assertTrue(result.hasFailures());
    }

    @Property
    public void validParentChildSubResources(List<@From(IpResourceGen.class) IpResource> parentResources, int childResourceCount) {
        if (parentResources.isEmpty()) {
            return;
        }

        final IpResourceSet parentResourceSet = new IpResourceSet(parentResources);

        // some part of the parent resources become child
        final IpResourceSet childResourceSet = new IpResourceSet(
            parentResources.subList(0, Math.abs(childResourceCount) % parentResources.size()));
        if (childResourceSet.isEmpty()) {
            return;
        }

        ValidationResult result = validateParentChildPair(parentResourceSet, childResourceSet);
        assertFalse(result.hasFailures());
    }

    @Property
    public void validParentChildOverClaiming(List<@From(IpResourceGen.class) IpResource> parentResources,
                                             int childResourceCount,
                                             List<@From(IpResourceGen.class) IpResource> extraChildResources) {
        if (parentResources.isEmpty()) {
            return;
        }

        final IpResourceSet parentResourceSet = new IpResourceSet(parentResources);
        final IpResourceSet childResourceSet = new IpResourceSet(extraChildResources);

        // some part of the parent resources become child
        parentResources.subList(0, Math.abs(childResourceCount) % parentResources.size()).forEach(childResourceSet::add);
        if (childResourceSet.isEmpty()) {
            return;
        }

        ValidationResult result = validateParentChildPair(parentResourceSet, childResourceSet);
        if (extraChildResources.isEmpty()) {
            assertFalse(result.hasFailures());
        } else {
            IpResourceSet overclaiming = new IpResourceSet(childResourceSet);
            overclaiming.removeAll(parentResourceSet);
            if (!overclaiming.isEmpty()) {
                final ValidationCheck failure = result.getFailuresForAllLocations().get(0);
                assertEquals("cert.resource.range.is.valid", failure.getKey());
                assertEquals(overclaiming.toString(), failure.getParams()[0]);
            }
        }
    }

    @Property
    public void validParentChildOverClaimingLooseValidation(List<@From(IpResourceGen.class) IpResource> parentResources,
                                                            int childResourceCount,
                                                            List<@From(IpResourceGen.class) IpResource> extraChildResources) {
        if (parentResources.isEmpty()) {
            return;
        }

        final IpResourceSet parentResourceSet = new IpResourceSet(parentResources);
        final IpResourceSet childResourceSet = new IpResourceSet(extraChildResources);

        // some part of the parent resources become child
        parentResources.subList(0, Math.abs(childResourceCount) % parentResources.size()).forEach(childResourceSet::add);
        if (childResourceSet.isEmpty()) {
            return;
        }

        ValidationResult result = validateParentChildReconsidered(parentResourceSet, childResourceSet);
        assertFalse(result.hasFailures());
        if (!extraChildResources.isEmpty()) {
            IpResourceSet overclaiming = new IpResourceSet(childResourceSet);
            overclaiming.removeAll(parentResourceSet);
            if (!overclaiming.isEmpty()) {
                final ValidationCheck warning = result.getWarnings().get(0);
                assertEquals("cert.resource.range.is.valid", warning.getKey());
                assertEquals(overclaiming.toString(), warning.getParams()[0]);
            }
        }
    }

    private ValidationResult validateParentChildReconsidered(IpResourceSet parentResourceSet, IpResourceSet childResourceSet) {
        return validateParentChildPairImpl(parentResourceSet, childResourceSet, true);
    }

    private ValidationResult validateParentChildPair(IpResourceSet parentResourceSet, IpResourceSet childResourceSet) {
        return validateParentChildPairImpl(parentResourceSet, childResourceSet, false);
    }

    private ValidationResult validateParentChildPairImpl(IpResourceSet parentResourceSet, IpResourceSet childResourceSet, boolean reconsidered) {
        final X509ResourceCertificate parentCertificate = createRootCertificateBuilder()
            .withResources(parentResourceSet)
            .build();

        final X509ResourceCertificate childCertificate = createChildCertificateBuilder()
            .withResources(childResourceSet)
            .withInheritedResourceTypes(EnumSet.noneOf(IpResourceType.class))
            .build();

        X509Crl rootCrl = getRootCRL().build(ROOT_KEY_PAIR.getPrivate());
        ValidationResult result = ValidationResult.withLocation("n/a");
        final X509ResourceCertificateValidator validator;
        if (reconsidered) {
            validator = new X509ResourceCertificateParentChildLooseValidator(options, result, rootCrl,
                new CertificateRepositoryObjectValidationContext(URI.create("rsync://parent.cer"), parentCertificate));
        } else {
            validator = new X509ResourceCertificateParentChildValidator(options, result, parentCertificate, rootCrl, parentResourceSet);
        }
        validator.validate("child.cer", childCertificate);
        return result;
    }


    private X509ResourceCertificate getRootResourceCertificate() {
        return createRootCertificateBuilder().build();
    }

    private X509ResourceCertificate getRootResourceCertificateWithInheritedResources() {
        return createRootCertificateBuilder().withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class)).withResources(new IpResourceSet()).build();
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
        builder.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));
        builder.withValidityPeriod(VALIDITY_PERIOD);
        return builder;
    }


    private X509CrlBuilder getRootCRL() {
        X509CrlBuilder builder = new X509CrlBuilder();

        builder.withIssuerDN(ROOT_CERTIFICATE_NAME);
        builder.withThisUpdateTime(VALIDITY_PERIOD.getNotValidBefore().plusDays(1));
        builder.withNextUpdateTime(UTC.dateTime().plusMonths(1));
        builder.withNumber(BigInteger.valueOf(1));
        builder.withAuthorityKeyIdentifier(ROOT_KEY_PAIR.getPublic());
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }

}
