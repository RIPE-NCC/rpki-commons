package net.ripe.rpki.commons.crypto.util;

import com.google.common.io.Files;
import com.google.common.io.Resources;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.UnknownCertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.aspa.AspaCms;
import net.ripe.rpki.commons.crypto.cms.aspa.AspaCmsTest;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlTest;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import static net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory.createCertificateRepositoryObject;
import static net.ripe.rpki.commons.validation.ValidationStatus.ERROR;
import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.assertj.core.api.Assertions.assertThat;


public class CertificateRepositoryObjectFactoryTest {

    @Test
    public void unknownFileExtensionsShouldProduceAnError() {
        byte[] encoded = {0, 1};
        String unknownFileExtension = "file.unknown";
        ValidationResult validationResult = ValidationResult.withLocation(unknownFileExtension);

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertThat(object).isInstanceOf(UnknownCertificateRepositoryObject.class);
        assertThat(encoded).isEqualTo(object.getEncoded());
        assertThat(validationResult.hasWarnings()).isFalse();
        assertThat(validationResult.hasFailures()).isTrue();
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(1);

        ValidationCheck check = validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE);
        assertThat(check.getStatus()).isEqualTo(ERROR);
        assertThat(Arrays.asList(check.getParams()).contains(unknownFileExtension));
    }

    @Test
    public void shouldParseResourceCertificate() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("certificate.cer"));
        X509ResourceCertificate cert = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();

        CertificateRepositoryObject object = createCertificateRepositoryObject(cert.getEncoded(), validationResult);

        assertThat(validationResult.hasFailureForCurrentLocation()).isFalse()
                .withFailMessage("no validation failures " + validationResult.getFailuresForCurrentLocation());
        assertThat(object).isInstanceOf(X509ResourceCertificate.class);
        assertThat(cert).isEqualTo(object);
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(32);
        assertThat(validationResult.hasNoFailuresOrWarnings()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(CERTIFICATE_PARSED).isOk()).isTrue();
    }

    @Test
    public void shouldParseMalformedResourceCertificate() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("certificate.cer"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertThat(object).isNull();
        assertThat(validationResult.getAllValidationChecksForCurrentLocation().size()).isEqualTo(2);
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(CERTIFICATE_PARSED).isOk()).isFalse();
    }

    @Test
    public void shouldParseRoaCms() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("roa.roa"));
        RoaCms roaCms = RoaCmsTest.getRoaCms();

        CertificateRepositoryObject object = createCertificateRepositoryObject(roaCms.getEncoded(), validationResult);

        assertThat(object).isInstanceOf(RoaCms.class);
        assertThat(roaCms).isEqualTo(object);
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(64);
        assertThat(validationResult.hasFailures()).isFalse();
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(CRLDP_OMITTED).getStatus()).isEqualTo(ValidationStatus.WARNING);
    }

    @Test
    public void shouldParseMalformedRoaCms() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("roa.roa"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertThat(object).isNull();
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(3);
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(CMS_DATA_PARSING).isOk()).isFalse();
        assertThat(validationResult.getResultForCurrentLocation(ROA_CONTENT_TYPE).isOk()).isFalse();
    }

    @Test
    public void shouldParseManifestCms() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("manifest.mft"));
        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();

        CertificateRepositoryObject object = createCertificateRepositoryObject(manifestCms.getEncoded(), validationResult);

        assertThat(object).isInstanceOf(ManifestCms.class);
        assertThat(manifestCms).isEqualTo(object);
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(67);
        assertThat(validationResult.hasNoFailuresOrWarnings()).isTrue()
                .withFailMessage("" + validationResult.getAllValidationChecksForCurrentLocation());
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
    }

    @Test
    public void shouldParseMalformedManifestCms() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("manifest.mft"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertThat(object).isNull();
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(2);
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(CMS_DATA_PARSING).isOk()).isFalse();
    }

    @Test
    public void shouldParseCrl() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("crl.crl"));
        X509Crl crl = X509CrlTest.createCrl();

        CertificateRepositoryObject object = createCertificateRepositoryObject(crl.getEncoded(), validationResult);

        assertThat(object).isInstanceOf(X509Crl.class);
        assertThat(crl).isEqualTo(object);
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(2);
        assertThat(validationResult.hasNoFailuresOrWarnings()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(CRL_PARSED).isOk()).isTrue();
    }

    @Test
    public void shouldParseMalformedCrl() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("crl.crl"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertThat(object).isNull();
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(2);
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(CRL_PARSED).isOk()).isFalse();
    }

    @Test
    public void shouldParseMalformedGhostbustersRecord() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("ghostbusters.gbr"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertThat(object).isNull();
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(3);
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
    }

    @Test
    public void shouldParseAspa() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("aspa.asa"));
        AspaCms aspa = AspaCmsTest.createAspa();

        CertificateRepositoryObject object = createCertificateRepositoryObject(aspa.getEncoded(), validationResult);

        assertThat(object).isInstanceOf(AspaCms.class);
        assertThat(aspa).isEqualTo(object);
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(63)
                .withFailMessage("" + validationResult.getAllValidationChecksForCurrentLocation());
        assertThat(validationResult.hasNoFailuresOrWarnings()).isTrue()
                .withFailMessage("" + validationResult.getAllValidationChecksForCurrentLocation());
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
        assertThat(validationResult.getResultForCurrentLocation(ASPA_CUSTOMER_ASN_CERTIFIED).isOk()).isTrue();
    }

    @Test
    public void shouldParseMalformedAspa() {
        byte[] encoded = { 0, 1 };
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("aspa.asa"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertThat(object).isNull();
        assertThat(validationResult.getAllValidationChecksForCurrentLocation()).hasSize(3)
                .withFailMessage("" + validationResult.getAllValidationChecksForCurrentLocation());
        assertThat(validationResult.hasNoFailuresOrWarnings()).isFalse()
                .withFailMessage("" + validationResult.getAllValidationChecksForCurrentLocation());
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isTrue();
    }

    /**
     * Test that it handles (but rejects) a number of unsupported RPKI files
     *   * Trust Anchor Key
     *   * Resource Signed Checklist
     */
    @ParameterizedTest(name = "{index} => {0} path={2}")
    @CsvSource({
            "interop/openbsd-regress/05F53BCE4DAA11EDB9AC0C5B9E174E93.tak",
            "interop/openbsd-regress/42AE70A64DA711EDB37796549E174E93.tak",
            "interop/openbsd-regress/B7C2334E4DA911EDAF862D5A9E174E93.tak",
            "interop/openbsd-regress/c6938fc00af6496d9d4e6e2d876e4b4811887b60f4f1bc9cd0b3cdb7c57c6d5e.sig",
            "interop/openbsd-regress/checklist-08.sig",
    })
    public void shouldParseUnsupportedFiles(String path) throws IOException {
        byte[] encoded = Resources.toByteArray(Resources.getResource(path));

        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation(path));
        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertThat(object).isNotNull();
        assertThat(object).isInstanceOf(UnknownCertificateRepositoryObject.class);
        assertThat(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk()).isFalse();
    }
}
