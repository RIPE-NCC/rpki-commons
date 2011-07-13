/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.x509cert;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.joda.time.DateTime;
import org.junit.Test;


public class X509ResourceCertificateParserTest {

    private static final X500Principal TEST_SELF_SIGNED_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final BigInteger TEST_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final IpResourceSet RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private static final ValidityPeriod TEST_VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));

    private X509ResourceCertificateParser subject = new X509ResourceCertificateParser();

    public static X509ResourceCertificateBuilder createPreconfiguredBuilder() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withSubjectDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withIssuerDN(TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withSerial(TEST_SERIAL_NUMBER);
        builder.withValidityPeriod(TEST_VALIDITY_PERIOD);
        builder.withPublicKey(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        builder.withResources(RESOURCE_SET);
        builder.withAuthorityKeyIdentifier(false);
        return builder;
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRequireResourceCertificatePolicy() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder().withPolicies(new PolicyInformation(new DERObjectIdentifier("1.2.3.4")));
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());
        subject.getCertificate();
    }

    @Test
    public void shouldParseResourceCertificateWhenResourceExtensionsArePresent() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());
        X509ResourceCertificate parsed = subject.getCertificate();

        assertTrue(parsed instanceof X509ResourceCertificate);
        assertEquals(certificate, parsed);
    }

    @Test
    public void shouldFailOnInvalidInput() {
        byte[] badlyEncoded = { 0x01, 0x03, 0x23 };
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse("badly", badlyEncoded);
        assertEquals(Arrays.asList(new ValidationCheck(false, CERTIFICATE_PARSED)), parser.getValidationResult().getFailures("badly"));
    }

    @Test
    public void shouldFailOnInvalidSignatureAlgorithm() {
        @SuppressWarnings("deprecation")
        X509ResourceCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder().withSignatureAlgorithm("MD5withRSA").build();

        subject.parse("certificate", certificate.getEncoded());

        assertTrue(subject.getValidationResult().hasFailures());
        assertTrue(subject.getValidationResult().hasFailuresForLocationAndKey("certificate", ValidationString.CERTIFICATE_SIGNATURE_ALGORITHM));
    }
}
