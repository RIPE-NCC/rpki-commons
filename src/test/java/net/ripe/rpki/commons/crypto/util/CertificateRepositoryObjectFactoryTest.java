package net.ripe.rpki.commons.crypto.util;

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
import org.junit.Test;

import java.util.Arrays;

import static net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory.createCertificateRepositoryObject;
import static net.ripe.rpki.commons.validation.ValidationStatus.ERROR;
import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;


public class CertificateRepositoryObjectFactoryTest {

    @Test
    public void unknownFileExtensionsShouldProduceAnError() {
        byte[] encoded = {0, 1};
        String unknownFileExtension = "file.unknown";
        ValidationResult validationResult = ValidationResult.withLocation(unknownFileExtension);

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertTrue(object instanceof UnknownCertificateRepositoryObject);
        assertEquals(encoded, object.getEncoded());
        assertFalse(validationResult.hasWarnings());
        assertTrue(validationResult.hasFailures());
        assertEquals(1, validationResult.getAllValidationChecksForCurrentLocation().size());
        ValidationCheck check = validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE);
        assertEquals(ERROR, check.getStatus());
        assertTrue(Arrays.asList(check.getParams()).contains(unknownFileExtension));
    }

    @Test
    public void shouldParseResourceCertificate() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("certificate.cer"));
        X509ResourceCertificate cert = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();

        CertificateRepositoryObject object = createCertificateRepositoryObject(cert.getEncoded(), validationResult);

        assertFalse("no validation failures " + validationResult.getFailuresForCurrentLocation(), validationResult.hasFailureForCurrentLocation());
        assertTrue(object instanceof X509ResourceCertificate);
        assertEquals(cert, object);
        assertEquals(32, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.hasNoFailuresOrWarnings());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
        assertTrue(validationResult.getResultForCurrentLocation(CERTIFICATE_PARSED).isOk());
    }

    @Test
    public void shouldParseMalformedResourceCertificate() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("certificate.cer"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertNull(object);
        assertEquals(2, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
        assertFalse(validationResult.getResultForCurrentLocation(CERTIFICATE_PARSED).isOk());
    }

    @Test
    public void shouldParseRoaCms() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("roa.roa"));
        RoaCms roaCms = RoaCmsTest.getRoaCms();

        CertificateRepositoryObject object = createCertificateRepositoryObject(roaCms.getEncoded(), validationResult);

        assertTrue(object instanceof RoaCms);
        assertEquals(roaCms, object);
        assertEquals(64, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertFalse(validationResult.hasFailures());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
        assertEquals(ValidationStatus.WARNING, validationResult.getResultForCurrentLocation(CRLDP_OMITTED).getStatus());
    }

    @Test
    public void shouldParseMalformedRoaCms() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("roa.roa"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertNull(object);
        assertEquals(3, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
        assertFalse(validationResult.getResultForCurrentLocation(CMS_DATA_PARSING).isOk());
        assertFalse(validationResult.getResultForCurrentLocation(ROA_CONTENT_TYPE).isOk());
    }

    @Test
    public void shouldParseManifestCms() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("manifest.mft"));
        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();

        CertificateRepositoryObject object = createCertificateRepositoryObject(manifestCms.getEncoded(), validationResult);

        assertTrue(object instanceof ManifestCms);
        assertEquals(manifestCms, object);
        assertEquals(67, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue("" + validationResult.getAllValidationChecksForCurrentLocation(), validationResult.hasNoFailuresOrWarnings());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
    }

    @Test
    public void shouldParseMalformedManifestCms() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("manifest.mft"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertNull(object);
        assertEquals(2, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
        assertFalse(validationResult.getResultForCurrentLocation(CMS_DATA_PARSING).isOk());
    }

    @Test
    public void shouldParseCrl() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("crl.crl"));
        X509Crl crl = X509CrlTest.createCrl();

        CertificateRepositoryObject object = createCertificateRepositoryObject(crl.getEncoded(), validationResult);

        assertTrue(object instanceof X509Crl);
        assertEquals(crl, object);
        assertEquals(2, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.hasNoFailuresOrWarnings());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
        assertTrue(validationResult.getResultForCurrentLocation(CRL_PARSED).isOk());
    }

    @Test
    public void shouldParseMalformedCrl() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("crl.crl"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertNull(object);
        assertEquals(2, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
        assertFalse(validationResult.getResultForCurrentLocation(CRL_PARSED).isOk());
    }

    @Test
    public void shouldParseMalformedGhostbustersRecord() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("ghostbusters.gbr"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertNull(object);
        assertEquals(3, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
    }

    @Test
    public void shouldParseAspa() {
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("aspa.asa"));
        AspaCms aspa = AspaCmsTest.createAspa();

        CertificateRepositoryObject object = createCertificateRepositoryObject(aspa.getEncoded(), validationResult);

        assertTrue(object instanceof AspaCms);
        assertEquals(aspa, object);
        assertEquals("" + validationResult.getAllValidationChecksForCurrentLocation(), 62, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue("" + validationResult.getAllValidationChecksForCurrentLocation(), validationResult.hasNoFailuresOrWarnings());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
        assertTrue(validationResult.getResultForCurrentLocation(ASPA_CUSTOMER_ASN_CERTIFIED).isOk());
    }

    @Test
    public void shouldParseMalformedAspa() {
        byte[] encoded = { 0, 1 };
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("aspa.asa"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertNull(object);
        assertEquals("" + validationResult.getAllValidationChecksForCurrentLocation(), 5, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertFalse("" + validationResult.getAllValidationChecksForCurrentLocation(), validationResult.hasNoFailuresOrWarnings());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
    }
}
