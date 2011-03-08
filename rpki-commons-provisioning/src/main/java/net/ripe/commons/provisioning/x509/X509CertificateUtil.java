package net.ripe.commons.provisioning.x509;

import java.io.IOException;
import java.security.cert.X509Extension;

import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
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
            throw new RuntimeException("Cannot get SubjectKeyIdentifier for certificate", e); //FIXME: use spicifc exception type
        }
    }
}
