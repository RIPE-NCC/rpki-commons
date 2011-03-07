package net.ripe.commons.certification.x509cert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Extension;

import java.security.cert.X509Certificate;

import net.ripe.commons.certification.Asn1Util;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public final class X509CertificateUtil {

    private X509CertificateUtil() {
        //Utility classes should not have a public or default constructor.
    }

    public static byte[] getSubjectKeyIdentifier(X509Extension certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
            if (extensionValue == null) {
                return null;
            }
            return SubjectKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();
        } catch (IOException e) {
            throw new X509PlainCertificateException("Cannot get SubjectKeyIdentifier for certificate", e);
        }
    }

    public static byte[] getAuthorityKeyIdentifier(X509Extension certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId());
            if (extensionValue == null) {
                return null;
            }
            return AuthorityKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();
        } catch (IOException e) {
            throw new X509PlainCertificateException("Can not get AuthorityKeyIdentifier for certificate", e);
        }
    }
    
    public static X509PlainCertificate parseDerEncoded(byte[] encoded) {
        X509CertificateParser<X509PlainCertificate> parser = X509CertificateParser.forPlainCertificate();
        parser.parse("certificate", encoded);
        return parser.getCertificate();
    }
    
    /**
     * Get a base 64-encoded, DER-encoded X.509 subjectPublicKeyInfo as used for the Trust Anchor Locator (TAL)
     * @throws X509PlainCertificateException
     * @throws IOException
     */
    public static String getEncodedSubjectPublicKeyInfo(X509Certificate certificate) {

        byte[] tbsCertificate;
        try {
            tbsCertificate = certificate.getTBSCertificate();
        } catch (CertificateEncodingException e) {
            throw new X509PlainCertificateException("Can't extract TBSCertificate from certificate", e);
        }
        ASN1Sequence tbsCertificateSequence = (ASN1Sequence) Asn1Util.decode(tbsCertificate);
        TBSCertificateStructure tbsCertificateStructure = new TBSCertificateStructure(tbsCertificateSequence);
        SubjectPublicKeyInfo subjectPublicKeyInfo = tbsCertificateStructure.getSubjectPublicKeyInfo();

        try {
            byte[] data = subjectPublicKeyInfo.getDEREncoded();
            Base64Encoder encoder = new Base64Encoder();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            encoder.encode(data, 0, data.length, out);
            out.flush();
            return out.toString();
        } catch (IOException e) {
            throw new X509PlainCertificateException("Can't encode SubjectPublicKeyInfo for certificate", e);
        }
    }
}
