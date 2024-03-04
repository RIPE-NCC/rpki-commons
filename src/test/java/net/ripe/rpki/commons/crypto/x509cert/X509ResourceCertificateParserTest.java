package net.ripe.rpki.commons.crypto.x509cert;

import com.google.common.io.Files;
import com.pholser.junit.quickcheck.From;
import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.generator.Size;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
import net.ripe.ipresource.ImmutableResourceSet;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.properties.URIGen;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelperTest.CAB_BASELINE_REQUIREMENTS_POLICY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST;
import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;



@RunWith(JUnitQuickcheck.class)
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
    public void shouldAcceptCertificateWithIdCtCps() throws IOException {
        byte[] encoded = Files.toByteArray(new File("src/test/resources/resourcecertificate/apnic-rpki-root-iana-origin-includes-policy-with-cps.cer"));

        subject.parse("certificate", encoded);
        assertTrue(subject.getValidationResult().hasNoFailuresOrWarnings());
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
        builder.withResources(ImmutableResourceSet.ALL_PRIVATE_USE_RESOURCES);
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

    @Property
    public void validURI(
            @From(URIGen.class) @URIGen.URIControls(schemas = { "rsync" }) URI manifestURI,
            @From(URIGen.class) @URIGen.URIControls(schemas = { "https" }) URI repoURI,
            @Size(min=0, max=100) List<@From(URIGen.class) @URIGen.URIControls(schemas = { "https" }) URI> crlURIs) {
        String name = "test";

        URI[] arrayURIs = new URI[crlURIs.size()];
        arrayURIs = crlURIs.toArray(arrayURIs);

        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest
                .createSelfSignedCaResourceCertificateBuilder()
                .withSubjectInformationAccess(
                    new X509CertificateInformationAccessDescriptor(ID_AD_RPKI_MANIFEST, manifestURI),
                    new X509CertificateInformationAccessDescriptor(ID_AD_CA_REPOSITORY, repoURI)
                ).withCrlDistributionPoints(arrayURIs);
        X509ResourceCertificate certificate = builder.build();

        // certificate built
        assertEquals(manifestURI, Arrays.stream(certificate.getSubjectInformationAccess()).filter(f -> f.getMethod().equals(ID_AD_RPKI_MANIFEST)).map(X509CertificateInformationAccessDescriptor::getLocation).findFirst().get());
        assertEquals(repoURI, Arrays.stream(certificate.getSubjectInformationAccess()).filter(f -> f.getMethod().equals(ID_AD_CA_REPOSITORY)).map(X509CertificateInformationAccessDescriptor::getLocation).findFirst().get());
        assertArrayEquals(arrayURIs, certificate.getCrlDistributionPoints());

        ValidationResult result = ValidationResult.withLocation(name);
        final AbstractX509CertificateWrapper certificateWrapper = X509ResourceCertificateParser.parseCertificate(result, certificate.getEncoded());
        assertNull(certificateWrapper);
        assertEquals(1, result.getFailuresForCurrentLocation().size());
        assertEquals(ValidationStatus.PASSED, result.getResult(new ValidationLocation(name), CERT_SIA_IS_PRESENT).getStatus());
        assertEquals(ValidationStatus.PASSED, result.getResult(new ValidationLocation(name), CERT_SIA_CA_REPOSITORY_URI_PRESENT).getStatus());
        assertEquals(ValidationStatus.ERROR, result.getResult(new ValidationLocation(name), CERT_SIA_CA_REPOSITORY_RSYNC_URI_PRESENT).getStatus());
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
