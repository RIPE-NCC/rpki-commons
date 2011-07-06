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

