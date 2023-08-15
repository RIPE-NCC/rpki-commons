package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;


public class X509CertificateUtilTest {

    @Test
    public void shouldGetEncodedSubjectPublicKeyInfo() {
        X509ResourceCertificate cert1 = X509ResourceCertificateTest.createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES).build();
        String encoded1 = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(cert1.getCertificate());

        X509ResourceCertificate cert2 = X509ResourceCertificateTest.createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES).build();
        String encoded2 = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(cert2.getCertificate());

        assertNotNull(encoded1);
        assertNotSame(encoded1, encoded2);
    }

    public static final String CERT_WITH_RRDP_URL =
        """
            -----BEGIN CERTIFICATE-----
            MIIFLTCCBBWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDEwJUQTAeFw0xNTAyMDMx
            NDUwMDFaFw0xNjAyMDMxNDUwMDFaMDMxMTAvBgNVBAMTKGJiODgyZmExYTZkMDA5ZTExMmYxMzgx
            MGE5ZGI0YjA0ZGJlNDlkMzYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCF840qoswP
            SXX07/0e7sGvagP7gBxoRjfGDsqjQ+Jj1uy2VNMeaeciFxrYRPmLPz8qNXYp11Q522tw33bM8Syl
            6p1AxjFD+mzj4Zes1xm6OSFo7DUPk7qlk3kvbOUoEVNpJL9kZMhc0F3gY5Sq6zNcR2CtiI5tHD3x
            ffIMQ+XVN1WcXkoGE96gm2GJmgvfUeEZo6fROLm9grIQDxIMmEF2GJemD/VEEgIjR4vjjqb0KcRY
            39fbHGrcJJND4qF3aYjmL7ZH4UKADtb6sxqAssyCiv1sNbFjHId8BjBlU2Xv+lf8Oe0qsSwXfdFj
            82qiJPv1NpRrlLlmR1z/hy5tDIhHAgMBAAGjggJwMIICbDAdBgNVHQ4EFgQUu4gvoabQCeES8TgQ
            qdtLBNvknTYwHwYDVR0jBBgwFoAU1y0ME/5462WgNp2rJAZwjNjnBfkwDwYDVR0TAQH/BAUwAwEB
            /zAOBgNVHQ8BAf8EBAMCAQYwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzAChidodHRwOi8vbG9j
            YWxob3N0OjgwODAvcnBraS1jYS90YS90YS5jZXIwggEsBggrBgEFBQcBCwSCAR4wggEaMFYGCCsG
            AQUFBzAFhkpyc3luYzovL2xvY2FsaG9zdDoxMDg3My9yZXBvLzNhODdhNGIxLTZlMjItNGE2My1h
            ZDBmLTA2ZjgzYWQzY2ExNi9kZWZhdWx0LzCBggYIKwYBBQUHMAqGdnJzeW5jOi8vbG9jYWxob3N0
            OjEwODczL3JlcG8vM2E4N2E0YjEtNmUyMi00YTYzLWFkMGYtMDZmODNhZDNjYTE2L2RlZmF1bHQv
            YmI4ODJmYTFhNmQwMDllMTEyZjEzODEwYTlkYjRiMDRkYmU0OWQzNi5tZnQwOwYIKwYBBQUHMA2G
            L2h0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9ycGtpLWNhL25vdGlmeS9ub3RpZnkueG1sMFoGA1UdHwRT
            MFEwT6BNoEuGSXJzeW5jOi8vbG9jYWxob3N0OjEwODczL3JlcG8vZDcyZDBjMTNmZTc4ZWI2NWEw
            MzY5ZGFiMjQwNjcwOGNkOGU3MDVmOS5jcmwwGAYDVR0gAQH/BA4wDDAKBggrBgEFBQcOAjAeBggr
            BgEFBQcBBwEB/wQPMA0wCwQCAAEwBQMDAMCoMA0GCSqGSIb3DQEBCwUAA4IBAQAxP3d4m66BZT1p
            yZcWeZeagSLD5jsXBZnrr9I62GDgWBMnrEL1euf8K6ZdaM7JZCiiuTtrseugTH4u1T81dtOD0E7X
            7ssK9dqExPaVRipE50AM4HZC4DSXh3NoQIaDrcPEVuqFCUF/P9Po7hq+JkzBSQDRuDNjBYgarzA/
            PdApSo+fQPHH8g28g24i9gn4CJDcc1g5UQVP4wCXn/Mmw7ZNrhwI12YqCQdNTID6Mx5gIFHlogCT
            cu3tN8Q36mohcdxFv/PM1nLY6IJ/+ym0xIfs51khS26/Nrf/jXMLXakIdonD8bRCzm47H6NTkwD3
            bzE3V+I05l3rdFdzd/6Nh2Ya-----END CERTIFICATE-----""";

    @Test
    //@Ignore
    public void shouldParseRrdpRepositoryUrl() throws java.security.cert.CertificateException {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(CERT_WITH_RRDP_URL.getBytes(StandardCharsets.UTF_8)));

        URI rrdpNotifyUri = X509CertificateUtil.getRrdpNotifyUri(certificate);

        assertEquals(URI.create("http://localhost:8080/rpki-ca/notify/notify.xml"), rrdpNotifyUri);
    }
}


