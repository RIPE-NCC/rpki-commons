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
package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import org.apache.commons.io.IOUtils;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.*;


public class X509CertificateUtilTest {

    @Test
    public void shouldGetEncodedSubjectPublicKeyInfo() throws CertificateEncodingException, IOException {
        X509ResourceCertificate cert1 = X509ResourceCertificateTest.createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES).build();
        String encoded1 = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(cert1.getCertificate());

        X509ResourceCertificate cert2 = X509ResourceCertificateTest.createSelfSignedCaCertificateBuilder().withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES).build();
        String encoded2 = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(cert2.getCertificate());

        assertNotNull(encoded1);
        assertNotSame(encoded1, encoded2);
    }

    public static final String CERT_WITH_RRDP_URL =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIFLTCCBBWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDEwJUQTAeFw0xNTAyMDMx\n"+
            "NDUwMDFaFw0xNjAyMDMxNDUwMDFaMDMxMTAvBgNVBAMTKGJiODgyZmExYTZkMDA5ZTExMmYxMzgx\n"+
            "MGE5ZGI0YjA0ZGJlNDlkMzYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCF840qoswP\n"+
            "SXX07/0e7sGvagP7gBxoRjfGDsqjQ+Jj1uy2VNMeaeciFxrYRPmLPz8qNXYp11Q522tw33bM8Syl\n"+
            "6p1AxjFD+mzj4Zes1xm6OSFo7DUPk7qlk3kvbOUoEVNpJL9kZMhc0F3gY5Sq6zNcR2CtiI5tHD3x\n"+
            "ffIMQ+XVN1WcXkoGE96gm2GJmgvfUeEZo6fROLm9grIQDxIMmEF2GJemD/VEEgIjR4vjjqb0KcRY\n"+
            "39fbHGrcJJND4qF3aYjmL7ZH4UKADtb6sxqAssyCiv1sNbFjHId8BjBlU2Xv+lf8Oe0qsSwXfdFj\n"+
            "82qiJPv1NpRrlLlmR1z/hy5tDIhHAgMBAAGjggJwMIICbDAdBgNVHQ4EFgQUu4gvoabQCeES8TgQ\n"+
            "qdtLBNvknTYwHwYDVR0jBBgwFoAU1y0ME/5462WgNp2rJAZwjNjnBfkwDwYDVR0TAQH/BAUwAwEB\n"+
            "/zAOBgNVHQ8BAf8EBAMCAQYwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzAChidodHRwOi8vbG9j\n"+
            "YWxob3N0OjgwODAvcnBraS1jYS90YS90YS5jZXIwggEsBggrBgEFBQcBCwSCAR4wggEaMFYGCCsG\n"+
            "AQUFBzAFhkpyc3luYzovL2xvY2FsaG9zdDoxMDg3My9yZXBvLzNhODdhNGIxLTZlMjItNGE2My1h\n"+
            "ZDBmLTA2ZjgzYWQzY2ExNi9kZWZhdWx0LzCBggYIKwYBBQUHMAqGdnJzeW5jOi8vbG9jYWxob3N0\n"+
            "OjEwODczL3JlcG8vM2E4N2E0YjEtNmUyMi00YTYzLWFkMGYtMDZmODNhZDNjYTE2L2RlZmF1bHQv\n"+
            "YmI4ODJmYTFhNmQwMDllMTEyZjEzODEwYTlkYjRiMDRkYmU0OWQzNi5tZnQwOwYIKwYBBQUHMA2G\n"+
            "L2h0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9ycGtpLWNhL25vdGlmeS9ub3RpZnkueG1sMFoGA1UdHwRT\n"+
            "MFEwT6BNoEuGSXJzeW5jOi8vbG9jYWxob3N0OjEwODczL3JlcG8vZDcyZDBjMTNmZTc4ZWI2NWEw\n"+
            "MzY5ZGFiMjQwNjcwOGNkOGU3MDVmOS5jcmwwGAYDVR0gAQH/BA4wDDAKBggrBgEFBQcOAjAeBggr\n"+
            "BgEFBQcBBwEB/wQPMA0wCwQCAAEwBQMDAMCoMA0GCSqGSIb3DQEBCwUAA4IBAQAxP3d4m66BZT1p\n"+
            "yZcWeZeagSLD5jsXBZnrr9I62GDgWBMnrEL1euf8K6ZdaM7JZCiiuTtrseugTH4u1T81dtOD0E7X\n"+
            "7ssK9dqExPaVRipE50AM4HZC4DSXh3NoQIaDrcPEVuqFCUF/P9Po7hq+JkzBSQDRuDNjBYgarzA/\n"+
            "PdApSo+fQPHH8g28g24i9gn4CJDcc1g5UQVP4wCXn/Mmw7ZNrhwI12YqCQdNTID6Mx5gIFHlogCT\n"+
            "cu3tN8Q36mohcdxFv/PM1nLY6IJ/+ym0xIfs51khS26/Nrf/jXMLXakIdonD8bRCzm47H6NTkwD3\n"+
            "bzE3V+I05l3rdFdzd/6Nh2Ya-----END CERTIFICATE-----";

    @Test
    @Ignore
    public void shouldParseRrdpRepositoryUrl() throws java.security.cert.CertificateException {
        final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(IOUtils.toInputStream(CERT_WITH_RRDP_URL));

        URI rrdpNotifyUri = X509CertificateUtil.getRrdpNotifyUri(certificate);

        assertEquals(URI.create("http://localhost:8080/rpki-ca/notify/notify.xml"), rrdpNotifyUri);
    }
}


