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
package net.ripe.rpki.commons.crypto.util;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.UnknownCertificateRepositoryObject;
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

        assertTrue(object instanceof X509ResourceCertificate);
        assertEquals(cert, object);
        assertEquals(16, validationResult.getAllValidationChecksForCurrentLocation().size());
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
        assertEquals(49, validationResult.getAllValidationChecksForCurrentLocation().size());
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
        assertEquals(49, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.hasNoFailuresOrWarnings());
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
    public void shouldParsemalformedGhostbustersRecord() {
        byte[] encoded = {0, 1};
        ValidationResult validationResult = ValidationResult.withLocation(new ValidationLocation("ghostbusters.gbr"));

        CertificateRepositoryObject object = createCertificateRepositoryObject(encoded, validationResult);

        assertNull(object);
        assertEquals(3, validationResult.getAllValidationChecksForCurrentLocation().size());
        assertTrue(validationResult.getResultForCurrentLocation(KNOWN_OBJECT_TYPE).isOk());
    }
}
