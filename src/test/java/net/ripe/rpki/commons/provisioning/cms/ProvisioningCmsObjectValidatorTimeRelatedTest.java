package net.ripe.rpki.commons.provisioning.cms;

import com.google.common.io.Files;
import lombok.SneakyThrows;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateParser;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class ProvisioningCmsObjectValidatorTimeRelatedTest {
    private ProvisioningCmsObject ca1CmsObject;
    private ProvisioningIdentityCertificate ca1IdCert;
    private ProvisioningIdentityCertificate ca2IdCert;

    private ValidationResult validationResult;

    private Clock clock = Clock.systemUTC();

    @BeforeEach
    public void setup() {
        validationResult = ValidationResult.withLocation("n/a");

        // Validity periods and signatures are not validated when reading
        ca1CmsObject = readProvisioningPDU("src/test/resources/interop/up-down/krill-ca1-list-pdu.der");
        ca1IdCert = readProvisioningIdentityCertificate("src/test/resources/interop/up-down/krill-ca1-id-cert.der");
        ca2IdCert = readProvisioningIdentityCertificate("src/test/resources/interop/up-down/krill-ca2-id-cert.der");
    }

    @SneakyThrows
    private static ProvisioningCmsObject readProvisioningPDU(String resourcePath) {
        ProvisioningCmsObjectParser cmsParser = new ProvisioningCmsObjectParser();
        cmsParser.parseCms("cms", Files.toByteArray(new File(resourcePath)));

        return cmsParser.getProvisioningCmsObject();
    }

    @SneakyThrows
    private static ProvisioningIdentityCertificate readProvisioningIdentityCertificate(String resourcePath) {
        ProvisioningIdentityCertificateParser certificateParser = new ProvisioningIdentityCertificateParser();
        certificateParser.parse("id-cert", Files.toByteArray(new File(resourcePath)));

        return certificateParser.getCertificate();
    }


    private void validateObjects(ValidationResult validationResult, ProvisioningCmsObject cmsObject, ProvisioningIdentityCertificate idCert) {
        validateObjectsWithLastSigningTime(validationResult, null, cmsObject, idCert);
    }


    private void validateObjectsWithLastSigningTime(ValidationResult validationResult, Instant lastSigningTime, ProvisioningCmsObject cmsObject, ProvisioningIdentityCertificate idCert) {
        ProvisioningCmsObjectValidator subject = new ProvisioningCmsObjectValidator(
                ValidationOptions.strictValidation(),
                Optional.ofNullable(lastSigningTime),
                cmsObject,
                idCert
        );

        subject.validate(validationResult.withClock(clock));
    }

    //
    // Test that path validation is performed
    //

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_cms_sig_not_from_id_cert() {
        clock = Clock.fixed(Instant.parse("2022-01-11T12:39:46.000Z"), ZoneOffset.UTC);

        assertThat(ca1IdCert.getPublicKey()).isNotEqualTo(ca2IdCert.getPublicKey());
        validateObjects(validationResult, ca1CmsObject, ca2IdCert);

        // The id certificates are different. Internally the validator rejects the CMS contents signature,
        // the CRL signature, the SKI because they all mismatch.
        assertThat(validationResult.hasFailures()).isTrue();
    }

    //
    // Test cases for validity period
    // - before id cert validity and EE validity
    // - before EE validity
    // - current
    // - EE expired
    // - both expired
    //

    @Test
    void testValidateProvisioningCmsAndIdentityCertificate_cms_ee_not_valid_yet() {
        clock = Clock.fixed(Instant.parse("2022-01-11T10:00:00Z"), ZoneOffset.UTC);

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_both_certs_not_valid_yet() {
        clock = Clock.fixed(Instant.parse("2022-01-11T10:00:00Z"), ZoneOffset.UTC);

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_current_certs() {
        clock = Clock.fixed(Instant.parse("2022-01-11T12:39:46.000Z"), ZoneOffset.UTC);

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_cms_ee_expired() {
        clock = Clock.fixed(Instant.parse("2022-01-13T12:39:46.000Z"), ZoneOffset.UTC);

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_two_expired_certs() {
        clock = Clock.fixed(Instant.parse("2024-01-11T10:00:00Z"), ZoneOffset.UTC);

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }

    //
    // Test cases for signing ime
    //
    // - no previous signing-time: all previous cases had no signing time.
    // - signing time after last
    // - signing time _at_ last
    // - signing time before last
    // Same CMS and ID cert as above, valid at the point in time set in the test.
    //

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_no_last() {
        clock = Clock.fixed(Instant.parse("2022-01-11T12:39:46.000Z"), ZoneOffset.UTC);

        validateObjectsWithLastSigningTime(validationResult, null, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_after_last() {
        clock = Clock.fixed(Instant.parse("2022-01-11T12:39:46.000Z"), ZoneOffset.UTC);

        validateObjectsWithLastSigningTime(validationResult, Instant.parse("2022-01-11T11:00:00.000Z"), ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_at_last() {
        clock = Clock.fixed(Instant.parse("2022-01-11T12:39:46.000Z"), ZoneOffset.UTC);

        validateObjectsWithLastSigningTime(validationResult, ca1CmsObject.getSigningTime(), ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    // i.e. replay of an object
    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_before_last() {
        clock = Clock.fixed(Instant.parse("2022-01-11T12:39:46.000Z"), ZoneOffset.UTC);

        validateObjectsWithLastSigningTime(validationResult, Instant.parse("2022-01-11T13:00:00.000Z"), ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }
}
