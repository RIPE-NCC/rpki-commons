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
package net.ripe.rpki.commons.crypto.x509cert;

import com.google.common.io.Files;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.commons.validation.ValidationString;
import org.apache.commons.io.FileUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.SECOND_TEST_KEY_PAIR;
import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.TEST_KEY_PAIR;
import static net.ripe.rpki.commons.validation.ValidationString.CERTIFICATE_PARSED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class X509RouterCertificateParserTest {

    private X509RouterCertificateParser subject = new X509RouterCertificateParser();

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireResourceCertificatePolicy() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder().withPolicies();
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());
        subject.getCertificate();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotParseResourceCertificateWhenResourceExtensionsArePresent() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());
        subject.getCertificate();
    }

    @Test
    public void shouldFailOnInvalidInput() {
        byte[] badlyEncoded = {0x01, 0x03, 0x23};
        subject.parse("badly", badlyEncoded);
        assertTrue(subject.getValidationResult().getFailures(new ValidationLocation("badly")).contains(new ValidationCheck(ValidationStatus.ERROR, CERTIFICATE_PARSED)));
    }

    @Test
    public void shouldFailOnInvalidSignatureAlgorithm() throws CertificateEncodingException {
        X509CertificateBuilderHelper builder = new X509CertificateBuilderHelper();
        builder.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        builder.withSerial(BigInteger.ONE);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = new DateTime(DateTimeZone.UTC);
        builder.withValidityPeriod(new ValidityPeriod(now, new DateTime(now.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        builder.withSignatureAlgorithm("MD5withRSA");
        X509Certificate certificate = builder.generateCertificate();

        subject.parse("certificate", certificate.getEncoded());

        assertTrue(subject.getValidationResult().hasFailures());
        assertFalse(subject.getValidationResult().getResult(new ValidationLocation("certificate"), ValidationString.CERTIFICATE_SIGNATURE_ALGORITHM).isOk());
    }

    @Test
    public void should_validate_key_algorithm_and_size() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());

        assertTrue(subject.getValidationResult().getResult(new ValidationLocation("certificate"), ValidationString.PUBLIC_KEY_CERT_ALGORITHM).isOk());
        assertTrue(subject.getValidationResult().getResult(new ValidationLocation("certificate"), ValidationString.PUBLIC_KEY_CERT_SIZE).isOk());
    }

    @Test
    public void should_parse_the_real_router_certificate() throws IOException {
        byte[] encoded = Files.toByteArray(new File("src/test/resources/router/router_certificate.cer"));

        subject.parse("certificate", encoded);
        final ValidationResult validationResult = subject.getValidationResult();
        assertFalse(validationResult.hasFailureForCurrentLocation());
        final X509RouterCertificate certificate = subject.getCertificate();
        assertNotNull(certificate);
    }

}
