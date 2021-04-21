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
package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.commons.validation.ValidationString;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelperTest.CAB_BASELINE_REQUIREMENTS_POLICY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST;
import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;


public class X509ResourceCertificateParserTest {

    private X509ResourceCertificateParser subject = new X509ResourceCertificateParser();

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireResourceCertificatePolicy() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        // Remove the default CPS policy
        X509CertificateBuilderTestUtils.setPoliciesOnBuilderHelperAttribute(builder);
        X509ResourceCertificate certificate = builder
                .build();

        subject.parse("certificate", certificate.getEncoded());
        subject.getCertificate();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailWhenOtherCertificatePolicyIsPresent() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        // Set another policy
        X509CertificateBuilderTestUtils.setPoliciesOnBuilderHelperAttribute(builder, CAB_BASELINE_REQUIREMENTS_POLICY);
        X509ResourceCertificate certificate = builder
                .build();

        subject.parse("certificate", certificate.getEncoded());
        subject.getCertificate();
    }

    @Test
    public void shouldParseResourceCertificateWhenResourceExtensionsArePresent() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509ResourceCertificate certificate = builder.build();

        subject.parse("certificate", certificate.getEncoded());
        X509ResourceCertificate parsed = subject.getCertificate();

        assertEquals(certificate, parsed);
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
        DateTime now = UTC.dateTime();
        builder.withValidityPeriod(new ValidityPeriod(now, new DateTime(now.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        builder.withSignatureAlgorithm("MD5withRSA");
        X509Certificate certificate = builder.generateCertificate();

        subject.parse("certificate", certificate.getEncoded());

        assertTrue(subject.getValidationResult().hasFailures());
        assertFalse(subject.getValidationResult().getResult(new ValidationLocation("certificate"), ValidationString.CERTIFICATE_SIGNATURE_ALGORITHM).isOk());
    }

    @Test
    public void should_validate_issuer_dn() {
        assertTrue("serialNumber optional", validateIssuerDn("CN=test"));
        assertFalse("mulitple serialNumbers not allowed", validateIssuerDn("CN=test, serialNumber=1, serialNumber=2"));
        assertFalse("single CN required", validateIssuerDn("serialNumber=1"));
        assertFalse("multiple CNs not allowed", validateIssuerDn("CN=foo, CN=bar, serialNumber=1"));
        assertFalse("only printable characters allowed for CN", validateIssuerDn("CN=test$, serialNumber=1"));
        assertFalse("only printable characters allowed for serialNumber", validateIssuerDn("CN=test, serialNumber=$"));
    }

    @Test
    public void should_validate_subject_dn() {
        assertTrue("serialNumber optional", validateSubjectDn("CN=test"));
        assertFalse("mulitple serialNumbers not allowed", validateSubjectDn("CN=test, serialNumber=1, serialNumber=2"));
        assertFalse("single CN required", validateSubjectDn("serialNumber=1"));
        assertFalse("multiple CNs not allowed", validateSubjectDn("CN=foo, CN=bar, serialNumber=1"));
        assertFalse("only printable characters allowed for CN", validateSubjectDn("CN=test$, serialNumber=1"));
        assertFalse("only printable characters allowed for serialNumber", validateSubjectDn("CN=test, serialNumber=$"));
    }

    @Test
    public void should_require_rsync_repository_uri() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder().withSubjectInformationAccess(
                new X509CertificateInformationAccessDescriptor(ID_AD_RPKI_MANIFEST, URI.create("rsync://example.com/repository/manifest.mft")),
                new X509CertificateInformationAccessDescriptor(ID_AD_CA_REPOSITORY, URI.create("https://example.com/repository/notify.xml"))
        );
        X509ResourceCertificate certificate = builder.build();

        ValidationResult result = ValidationResult.withLocation("test");
        final AbstractX509CertificateWrapper certificateWrapper = X509ResourceCertificateParser.parseCertificate(result, certificate.getEncoded());
        assertNull(certificateWrapper);
        assertEquals(1, result.getFailuresForCurrentLocation().size());
        assertEquals(ValidationStatus.PASSED, result.getResult(new ValidationLocation("test"), CERT_SIA_IS_PRESENT).getStatus());
        assertEquals(ValidationStatus.PASSED, result.getResult(new ValidationLocation("test"), CERT_SIA_CA_REPOSITORY_URI_PRESENT).getStatus());
        assertEquals(ValidationStatus.ERROR, result.getResult(new ValidationLocation("test"), CERT_SIA_CA_REPOSITORY_RSYNC_URI_PRESENT).getStatus());
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
    public void should_parse_resource_certificate_when_its_unknown() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        X509ResourceCertificate certificate = builder.build();

        ValidationResult result = ValidationResult.withLocation("test");
        final AbstractX509CertificateWrapper certificateWrapper = X509ResourceCertificateParser.parseCertificate(result, certificate.getEncoded());
        assertTrue(certificateWrapper instanceof X509ResourceCertificate);
        X509ResourceCertificate parsed = (X509ResourceCertificate) certificateWrapper;
        assertEquals(parsed.getPublicKey(), certificate.getPublicKey());
        assertEquals(parsed.getResources(), certificate.getResources());
    }

    @Test
    public void should_parse_router_certificate_when_its_unknown() {
        X509RouterCertificateBuilder builder = X509RouterCertificateTest.createSelfSignedRouterCertificateBuilder().withAsns(new int[]{1, 2, 3});
        X509RouterCertificate certificate = builder.build();

        ValidationResult result = ValidationResult.withLocation("test");
        final AbstractX509CertificateWrapper certificateWrapper = X509ResourceCertificateParser.parseCertificate(result, certificate.getEncoded());
        assertTrue(certificateWrapper instanceof X509RouterCertificate);
        X509RouterCertificate parsed = (X509RouterCertificate) certificateWrapper;
        assertEquals(parsed.getPublicKey(), certificate.getPublicKey());
    }

    private boolean validateIssuerDn(String name) {
        X509ResourceCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder()
                .withCrlDistributionPoints(URI.create("rsync://rpki.example.com/crl.crl"))
                .withIssuerDN(new X500Principal(name))
                .build();

        subject.parse("certificate", certificate.getEncoded());

        return subject.getValidationResult().getFailuresForCurrentLocation().isEmpty();
    }

    private boolean validateSubjectDn(String name) {
        X509ResourceCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder()
                .withCrlDistributionPoints(URI.create("rsync://rpki.example.com/crl.crl"))
                .withSubjectDN(new X500Principal(name))
                .build();

        subject.parse("certificate", certificate.getEncoded());

        return subject.getValidationResult().getFailuresForCurrentLocation().isEmpty();
    }
}
