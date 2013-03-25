/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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
import net.ripe.rpki.commons.validation.*;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;


public class CertificateRepositoryObjectFactoryTest {

    private ValidationResult validationResult;

    @Before
    public void setUp() {
        validationResult = ValidationResult.withLocation("unknown.crl");
    }

    @Test
    public void unknownFileExtensionsShouldProduceAWarning() {

        String unknownFilename = "foo.crl.gbr";
        byte[] encoded = null; // this will not get inspected, so we don't care what's in it
        ValidationLocation validationLocation = new ValidationLocation(unknownFilename);
        validationResult.setLocation(validationLocation);

        CertificateRepositoryObject cro = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded, validationResult);
        assertTrue(cro instanceof UnknownCertificateRepositoryObject);

        UnknownCertificateRepositoryObject unknownCertificateRepositoryObject = (UnknownCertificateRepositoryObject) cro;
        assertTrue(Arrays.equals(unknownCertificateRepositoryObject.getEncoded(), encoded));

        List<ValidationCheck> warnings = validationResult.getWarnings();
        assertTrue("we should find exactly one warning", warnings.size() == 1);
        ValidationCheck warning = warnings.get(0);
        assertTrue(warning.getStatus() == ValidationStatus.WARNING);
        assertTrue(warning.getKey().equals(CertificateRepositoryObjectFactory.CERTIFICATE_REPOSITORY_UNKNOWN_OBJECT_TYPE_MESSAGE_KEY));
        assertTrue("the name of the object will appear in the user feedback", Arrays.asList(warning.getParams()).contains(unknownFilename));
    }

    @Test(expected = CertificateRepositoryObjectParserException.class)
    public void shouldNotParseIllegalByteString() {
        validationResult.setLocation(new ValidationLocation("foo.cer"));
        byte[] encoded = new byte[]{0};
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded, validationResult);
        assertNull(object);
    }

    @Test
    public void shouldParseResourceCertificate() {

        validationResult.setLocation(new ValidationLocation("foo.cer"));

        X509ResourceCertificate cert = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(cert.getEncoded(), validationResult);
        assertEquals(cert, object);
        assertTrue(validationResult.getResult(validationResult.getCurrentLocation(), ValidationString.PUBLIC_KEY_CERT_SIZE).isOk());
    }

    @Test
    public void shouldParseRoaCms() {

        validationResult.setLocation(new ValidationLocation("foo.roa"));

        RoaCms roaCms = RoaCmsTest.getRoaCms();
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(roaCms.getEncoded(), validationResult);
        assertEquals(roaCms, object);
    }

    @Test
    public void shouldParseManifestCms() {

        validationResult.setLocation(new ValidationLocation("foo.mft"));

        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(manifestCms.getEncoded(), validationResult);
        assertEquals(manifestCms, object);
    }

    @Test
    public void shouldParseCrl() {

        validationResult.setLocation(new ValidationLocation("foo.crl"));

        X509Crl crl = X509CrlTest.createCrl();
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(crl.getEncoded(), validationResult);
        assertEquals(crl, object);
    }
}

