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
package net.ripe.commons.certification.util;

import static org.junit.Assert.assertEquals;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsTest;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlTest;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;

import org.junit.Test;


public class CertificateRepositoryObjectFactoryTest {

    @Test(expected=CertificateRepositoryObjectParserException.class)
    public void shouldNotParseIllegalByteString() {
        byte[] encoded = new byte[] {0};
        CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded);
    }

    @Test
    public void shoudParseResourceCertificate() {
        X509ResourceCertificate cert = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(cert.getEncoded());
        assertEquals(cert, object);
    }

    @Test
    public void shouldParseRoaCms() {
        RoaCms roaCms = RoaCmsTest.getRoaCms();
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(roaCms.getEncoded());
        assertEquals(roaCms, object);
    }

    @Test
    public void shouldParseManifestCms() {
        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(manifestCms.getEncoded());
        assertEquals(manifestCms, object);
    }

    @Test
    public void shouldParseCrl() {
        X509Crl crl = X509CrlTest.createCrl();
        CertificateRepositoryObject object = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(crl.getEncoded());
        assertEquals(crl, object);
    }
}

