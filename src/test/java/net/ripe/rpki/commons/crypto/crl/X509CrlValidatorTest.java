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
package net.ripe.rpki.commons.crypto.crl;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
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
    private static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));

    private static final KeyPair ROOT_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    private static final KeyPair FIRST_CHILD_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    private X509CrlValidator subject;
    private X509ResourceCertificate parent;

    private ValidationOptions options;
    private ValidationResult result;


    @Before
    public void setUp() {
        parent = getRootResourceCertificate();
        options = new ValidationOptions();
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
    public void shouldWarnWhenNextUpdatePassedWithinMaxStaleDays() {

        options.setMaxStaleDays(1);

        DateTime nextUpdateTime = new DateTime(DateTimeZone.UTC).minusSeconds(1).withMillisOfSecond(0);
        X509Crl crl = getRootCRL().withNextUpdateTime(nextUpdateTime).build(ROOT_KEY_PAIR.getPrivate());
        subject.validate("location", crl);

        result = subject.getValidationResult();
        assertFalse(result.hasFailures());
        assertEquals(new ValidationCheck(ValidationStatus.WARNING, CRL_NEXT_UPDATE_BEFORE_NOW, nextUpdateTime.toString()), result.getResult(new ValidationLocation("location"), CRL_NEXT_UPDATE_BEFORE_NOW));
    }

    @Test
    public void shouldNotRejectWhenNextUpdateTooLongAgo() {
        DateTime nextUpdateTime = new DateTime(DateTimeZone.UTC).minusSeconds(1).withMillisOfSecond(0);
        X509Crl crl = getRootCRL().withNextUpdateTime(nextUpdateTime).build(ROOT_KEY_PAIR.getPrivate());
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
