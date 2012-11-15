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
package net.ripe.commons.certification.x509cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import net.ripe.commons.certification.Asn1Util;
import net.ripe.commons.certification.validation.ValidationLocation;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public final class X509CertificateUtil {

    private X509CertificateUtil() {
        //Utility classes should not have a public or default constructor.
    }

    public static byte[] getSubjectKeyIdentifier(X509Extension certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(org.bouncycastle.asn1.x509.X509Extension.subjectKeyIdentifier.getId());
            if (extensionValue == null) {
                return null;
            }
            return SubjectKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();
        } catch (IOException e) {
            throw new AbstractX509CertificateWrapperException("Cannot get SubjectKeyIdentifier for certificate", e);
        }
    }

    public static byte[] getAuthorityKeyIdentifier(X509Extension certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(org.bouncycastle.asn1.x509.X509Extension.authorityKeyIdentifier.getId());
            if (extensionValue == null) {
                return null;
            }
            return AuthorityKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();
        } catch (IOException e) {
            throw new AbstractX509CertificateWrapperException("Can not get AuthorityKeyIdentifier for certificate", e);
        }
    }

    public static X509ResourceCertificate parseDerEncoded(byte[] encoded) {
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse(new ValidationLocation("certificate"), encoded);
        return parser.getCertificate();
    }

    /**
     * Get a base 64-encoded, DER-encoded X.509 subjectPublicKeyInfo as used for the Trust Anchor Locator (TAL)
     * @throws AbstractX509CertificateWrapperException
     * @throws IOException
     */
    public static String getEncodedSubjectPublicKeyInfo(X509Certificate certificate) {

        byte[] tbsCertificate;
        try {
            tbsCertificate = certificate.getTBSCertificate();
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException("Can't extract TBSCertificate from certificate", e);
        }
        ASN1Sequence tbsCertificateSequence = (ASN1Sequence) Asn1Util.decode(tbsCertificate);
        TBSCertificateStructure tbsCertificateStructure = new TBSCertificateStructure(tbsCertificateSequence);
        SubjectPublicKeyInfo subjectPublicKeyInfo = tbsCertificateStructure.getSubjectPublicKeyInfo();

        try {
            byte[] data = subjectPublicKeyInfo.getEncoded();
            Base64Encoder encoder = new Base64Encoder();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            encoder.encode(data, 0, data.length, out);
            out.flush();
            return out.toString();
        } catch (IOException e) {
            throw new AbstractX509CertificateWrapperException("Can't encode SubjectPublicKeyInfo for certificate", e);
        }
    }
}
