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
package net.ripe.rpki.commons.validation.properties;

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
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateParentChildValidator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.runner.RunWith;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


@RunWith(JUnitQuickcheck.class)
public class X509ResourceCertificateParentChildValidatorPropertyTest {

    private static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final DateTime NOW = UTC.dateTime();
    private static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(NOW.minusMinutes(1), NOW.plusYears(1));

    private static final X500Principal FIRST_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=First Child, C=NL");
    private static final BigInteger FIRST_CHILD_SERIAL_NUMBER = ROOT_SERIAL_NUMBER.add(BigInteger.valueOf(1));

    private static final KeyPair ROOT_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    private static final KeyPair FIRST_CHILD_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    private ValidationResult result;

    private ValidationOptions options;

    @Before
    public void setUp() {
        result = ValidationResult.withLocation("n/a");
        options = ValidationOptions.strictValidation();
    }

    @Property
    public void validParentChildSubResources(List<@From(IpResourceGen.class) IpResource> parentResources, int childResourceCount) {
        if (parentResources.isEmpty()) {
            return;
        }

        final IpResourceSet parentResourceSet = new IpResourceSet();
        final IpResourceSet childResourceSet = new IpResourceSet();

        parentResources.forEach(parentResourceSet::add);

        // some part of the parent resources become child
        parentResources.subList(0, Math.abs(childResourceCount) % parentResources.size()).forEach(childResourceSet::add);
        if (childResourceSet.isEmpty()) {
            return;
        }

        final X509ResourceCertificate parentCertificate = createRootCertificateBuilder()
            .withResources(parentResourceSet)
            .build();

        final X509ResourceCertificate childCertificate = createChildCertificateBuilder()
            .withResources(childResourceSet)
            .build();

        X509Crl rootCrl = getRootCRL().build(ROOT_KEY_PAIR.getPrivate());
        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(
            options, result, parentCertificate, rootCrl, parentResourceSet);

        validator.validate("child.cer", childCertificate);
        assertFalse(result.hasFailures());
    }

    @Property
    public void validParentChildOverClaiming(List<@From(IpResourceGen.class) IpResource> parentResources,
                                             int childResourceCount,
                                             List<@From(IpResourceGen.class) IpResource> extraChildResources) {
        if (parentResources.isEmpty()) {
            return;
        }

        final IpResourceSet parentResourceSet = new IpResourceSet();
        final IpResourceSet childResourceSet = new IpResourceSet(extraChildResources);

        parentResources.forEach(parentResourceSet::add);

        // some part of the parent resources become child
        parentResources.subList(0, Math.abs(childResourceCount) % parentResources.size()).forEach(childResourceSet::add);
        if (childResourceSet.isEmpty()) {
            return;
        }

        final X509ResourceCertificate parentCertificate = createRootCertificateBuilder()
            .withResources(parentResourceSet)
            .build();

        final X509ResourceCertificate childCertificate = createChildCertificateBuilder()
            .withResources(childResourceSet)
            .build();

        X509Crl rootCrl = getRootCRL().build(ROOT_KEY_PAIR.getPrivate());
        X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(
            options, result, parentCertificate, rootCrl, parentResourceSet);

        validator.validate("child.cer", childCertificate);
        if (extraChildResources.isEmpty()) {
            assertFalse(result.hasFailures());
        } else {
            assertTrue(result.hasFailures());
        }
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
