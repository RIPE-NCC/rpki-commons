package net.ripe.rpki.commons.provisioning.cms;

import com.google.common.io.Files;
import lombok.SneakyThrows;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateParser;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

public class ProvisioningCmsObjectValidatorTimeRelatedTest {
    private ProvisioningCmsObject ca1CmsObject;
    private ProvisioningIdentityCertificate ca1IdCert;
    private ProvisioningIdentityCertificate ca2IdCert;

    private ValidationResult validationResult;

    @BeforeEach
    public void setup() {
        validationResult = ValidationResult.withLocation("n/a");

        // Validity periods and signatures are not validated when reading
        ca1CmsObject = readProvisioningPDU("src/test/resources/interop/up-down/krill-ca1-list-pdu.der");
        ca1IdCert = readProvisioningIdentityCertificate("src/test/resources/interop/up-down/krill-ca1-id-cert.der");
        ca2IdCert = readProvisioningIdentityCertificate("src/test/resources/interop/up-down/krill-ca2-id-cert.der");
    }

    @AfterEach
    public void restoreClock() {
        DateTimeUtils.setCurrentMillisSystem();
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


    private static void validateObjects(ValidationResult validationResult, ProvisioningCmsObject cmsObject, ProvisioningIdentityCertificate idCert) {
        validateObjectsWithLastSigningTime(validationResult, null, cmsObject, idCert);
    }


    private static void validateObjectsWithLastSigningTime(ValidationResult validationResult, DateTime lastSigningTime, ProvisioningCmsObject cmsObject, ProvisioningIdentityCertificate idCert) {
        ProvisioningCmsObjectValidator subject = new ProvisioningCmsObjectValidator(
                ValidationOptions.strictValidation(),
                Optional.ofNullable(lastSigningTime),
                cmsObject,
                idCert
        );

        subject.validate(validationResult);
    }

    //
    // Test that path validation is performed
    //

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_cms_sig_not_from_id_cert() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T12:39:46.000Z").getMillis());

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
    public void testValidateProvisioningCmsAndIdentityCertificate_cms_ee_not_valid_yet() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T10:00:00Z").getMillis());

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_both_certs_not_valid_yet() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2021-01-11T10:00:00Z").getMillis());

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_current_certs() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T12:39:46.000Z").getMillis());

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_cms_ee_expired() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-13T12:39:46.000Z").getMillis());

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_two_expired_certs() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2040-01-11T10:00:00Z").getMillis());

        validateObjects(validationResult, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }

    //
    // Test cases for signing ime
    // - no current signing time.
    // - no current signing time, no last
    //
    // - no previous signing-time: all previous cases had no signing time.
    // - signing time after last
    // - signing time _at_ last
    // - signing time before last
    // Same CMS and ID cert as above, valid at the point in time set in the test.
    //
    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_no_current() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T12:39:46.000Z").getMillis());

        final ProvisioningCmsObject cmsObjectWithoutSigningTime = new ProvisioningCmsObject(
                ca1CmsObject.getEncoded(), ca1CmsObject.getCmsCertificate(), ca1CmsObject.getCaCertificates(),
                ca1CmsObject.getCrl(), ca1CmsObject.getPayload(), Optional.empty()
        );

        validateObjectsWithLastSigningTime(validationResult, DateTime.parse("2022-01-11T11:00:00.000Z"), cmsObjectWithoutSigningTime, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_no_current_no_last() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T12:39:46.000Z").getMillis());

        final ProvisioningCmsObject cmsObjectWithoutSigningTime = new ProvisioningCmsObject(
                ca1CmsObject.getEncoded(), ca1CmsObject.getCmsCertificate(), ca1CmsObject.getCaCertificates(),
                ca1CmsObject.getCrl(), ca1CmsObject.getPayload(), Optional.empty()
        );

        validateObjectsWithLastSigningTime(validationResult, null, cmsObjectWithoutSigningTime, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_no_last() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T12:39:46.000Z").getMillis());

        validateObjectsWithLastSigningTime(validationResult, null, ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_after_last() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T12:39:46.000Z").getMillis());

        validateObjectsWithLastSigningTime(validationResult, DateTime.parse("2022-01-11T11:00:00.000Z"), ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_at_last() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T12:39:46.000Z").getMillis());

        validateObjectsWithLastSigningTime(validationResult, ca1CmsObject.getSigningTime(), ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    // i.e. replay of an object
    @Test
    public void testValidateProvisioningCmsAndIdentityCertificate_signing_time_before_last() throws IOException {
        DateTimeUtils.setCurrentMillisFixed(DateTime.parse("2022-01-11T12:39:46.000Z").getMillis());

        validateObjectsWithLastSigningTime(validationResult, DateTime.parse("2022-01-11T13:00:00.000Z"), ca1CmsObject, ca1IdCert);
        assertThat(validationResult.hasFailures()).isTrue();
    }
}
