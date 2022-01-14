package net.ripe.rpki.commons.crypto.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.StoreException;

import javax.security.auth.x500.X500Principal;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public final class BouncyCastleUtil {

    public static final DigestCalculatorProvider DIGEST_CALCULATOR_PROVIDER = new BcDigestCalculatorProvider();

    private BouncyCastleUtil() {
    }

    public static final class X509CRLHolderStoreSelector implements Selector<Encodable> {
        @Override
        public boolean match(Encodable obj) {
            return obj instanceof X509CRLHolder;
        }

        @Override
        public Object clone() {
            return this;
        }
    }

    public static final class X509CertificateHolderStoreSelector implements Selector<Encodable> {
        @Override
        public boolean match(Encodable obj) {
            return obj instanceof X509CertificateHolder;
        }

        @Override
        public Object clone() {
            return this;
        }
    }

    /**
     * NOTE: JcaX509ExtensionUtils is not tread safe.
     * We always need to get a new instance of it.
     *
     * @return a new instance of JcaX509ExtensionUtils
     */
    private static JcaX509ExtensionUtils newJcaX509ExtensionUtils() {
        try {
            return new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static AuthorityKeyIdentifier createAuthorityKeyIdentifier(PublicKey publicKey) {
        return newJcaX509ExtensionUtils().createAuthorityKeyIdentifier(publicKey);
    }

    public static SubjectKeyIdentifier createSubjectKeyIdentifier(PublicKey publicKey) {
        return newJcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
    }

    public static X500Name principalToName(X500Principal dn) {
        return X500Name.getInstance(dn.getEncoded());
    }

    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(PublicKey key) {
        return SubjectPublicKeyInfo.getInstance(key.getEncoded());
    }

    public static X509Certificate holderToCertificate(X509CertificateHolder holder) throws CertificateException {
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    public static List<? extends X509Certificate> extractCertificates(CMSSignedDataParser signedDataParser) throws StoreException, CMSException, CertificateException {
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> holders = signedDataParser.getCertificates().getMatches(new X509CertificateHolderStoreSelector());
        List<X509Certificate> result = new ArrayList<X509Certificate>();
        for (X509CertificateHolder holder : holders) {
            result.add(holderToCertificate(holder));
        }
        return result;
    }

    public static X509CRL holderToCrl(X509CRLHolder holder) throws CRLException {
        return new JcaX509CRLConverter().getCRL(holder);
    }

    public static List<? extends X509CRL> extractCrls(CMSSignedDataParser signedDataParser) throws StoreException, CMSException, CRLException {
        @SuppressWarnings("unchecked")
        Collection<X509CRLHolder> holders = signedDataParser.getCRLs().getMatches(new X509CRLHolderStoreSelector());
        List<X509CRL> result = new ArrayList<X509CRL>();
        for (X509CRLHolder holder : holders) {
            result.add(holderToCrl(holder));
        }
        return result;
    }
}
