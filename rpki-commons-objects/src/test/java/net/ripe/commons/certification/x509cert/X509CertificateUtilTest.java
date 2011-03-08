package net.ripe.commons.certification.x509cert;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;

import net.ripe.ipresource.IpResourceSet;

import org.junit.Test;


public class X509CertificateUtilTest {

    
    @Test
    public void shouldGetEncodedSubjectPublicKeyInfo() throws CertificateEncodingException, IOException {
        X509ResourceCertificate cert1 = X509ResourceCertificateTest.createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES).buildResourceCertificate();
        String encoded1 = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(cert1.getCertificate());

        X509ResourceCertificate cert2 = X509ResourceCertificateTest.createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES).buildResourceCertificate();
        String encoded2 = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(cert2.getCertificate());

        assertNotNull(encoded1);
        assertNotSame(encoded1, encoded2);
    }
}


