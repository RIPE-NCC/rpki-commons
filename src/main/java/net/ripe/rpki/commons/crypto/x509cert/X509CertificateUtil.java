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
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionParser;
import net.ripe.rpki.commons.crypto.rfc8209.RouterExtensionEncoder;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;

public final class X509CertificateUtil {

    private X509CertificateUtil() {
        //Utility classes should not have a public or default constructor.
    }

    public static byte[] getSubjectKeyIdentifier(X509Extension certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId());
            if (extensionValue == null) {
                return null;
            }
            return SubjectKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();
        } catch (IOException e) {
            throw new X509CertificateOperationException("Cannot get SubjectKeyIdentifier for certificate", e);
        }
    }

    public static byte[] getAuthorityKeyIdentifier(X509Extension certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier.getId());
            if (extensionValue == null) {
                return null;
            }
            return AuthorityKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();
        } catch (IOException e) {
            throw new X509CertificateOperationException("Can not get AuthorityKeyIdentifier for certificate", e);
        }
    }

    public static X509ResourceCertificate parseDerEncoded(byte[] encoded) {
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse(ValidationResult.withLocation("unknown.cer"), encoded);
        return parser.getCertificate();
    }

    /**
     * Get a base 64-encoded, DER-encoded X.509 subjectPublicKeyInfo as used for the Trust Anchor Locator (TAL)
     *
     * @throws X509CertificateOperationException
     *
     * @throws IOException
     */
    public static String getEncodedSubjectPublicKeyInfo(X509Certificate certificate) {

        byte[] tbsCertificate;
        try {
            tbsCertificate = certificate.getTBSCertificate();
        } catch (CertificateEncodingException e) {
            throw new X509CertificateOperationException("Can't extract TBSCertificate from certificate", e);
        }
        ASN1Sequence tbsCertificateSequence = (ASN1Sequence) Asn1Util.decode(tbsCertificate);
        TBSCertificate tbsCertificateStructure = TBSCertificate.getInstance(tbsCertificateSequence);
        SubjectPublicKeyInfo subjectPublicKeyInfo = tbsCertificateStructure.getSubjectPublicKeyInfo();

        try {
            byte[] data = subjectPublicKeyInfo.getEncoded();
            Base64Encoder encoder = new Base64Encoder();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            encoder.encode(data, 0, data.length, out);
            out.flush();
            return out.toString();
        } catch (IOException e) {
            throw new X509CertificateOperationException("Can't encode SubjectPublicKeyInfo for certificate", e);
        }
    }

    public static boolean isRoot(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    }

    public static boolean isCa(X509Certificate certificate) {
        try {
            byte[] basicConstraintsExtension = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.basicConstraints.getId());
            if (basicConstraintsExtension == null) {
                /**
                 * The Basic Constraints extension field [...] MUST be present when
                 * the Subject is a CA, and MUST NOT be present otherwise.
                 * http://tools.ietf.org/html/draft-ietf-sidr-res-certs-21#section-4.9.1
                 */
                return false;
            }
            BasicConstraints constraints = BasicConstraints.getInstance(X509ExtensionUtil.fromExtensionValue(basicConstraintsExtension));
            return constraints.isCA();
        } catch (IOException e) {
            throw new X509CertificateOperationException(e);
        }
    }

    public static boolean isEe(X509Certificate certificate) {
        return !isCa(certificate);
    }

    public static boolean isRouter(X509Certificate certificate) {
        try {
            final List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
            return extendedKeyUsage != null && extendedKeyUsage.contains(RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER.getId());
        } catch (CertificateParsingException e) {
            throw new X509CertificateOperationException(e);
        }
    }

    public static X509CertificateInformationAccessDescriptor[] getAuthorityInformationAccess(X509Certificate certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess.getId());
            if (extensionValue == null) {
                return null;
            }
            AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getAccessDescriptions();
            return X509CertificateInformationAccessDescriptor.convertAccessDescriptors(accessDescriptions);
        } catch (IOException e) {
            throw new X509CertificateOperationException(e);
        }
    }

    public static X509CertificateInformationAccessDescriptor[] getSubjectInformationAccess(X509Certificate certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.subjectInfoAccess.getId());
            if (extensionValue == null) {
                return null;
            }
            AccessDescription[] accessDescriptions = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getAccessDescriptions();
            return X509CertificateInformationAccessDescriptor.convertAccessDescriptors(accessDescriptions);
        } catch (IOException e) {
            throw new X509CertificateOperationException(e);
        }
    }

    public static URI findFirstAuthorityInformationAccessByMethod(X509Certificate certificate, ASN1ObjectIdentifier method) {
        Validate.notNull(method, "method is null");
        return findFirstByMethod(method, "rsync", getAuthorityInformationAccess(certificate));
    }

    public static URI findFirstSubjectInformationAccessByMethod(X509Certificate certificate, ASN1ObjectIdentifier method) {
        Validate.notNull(method, "method is null");
        return findFirstByMethod(method, "rsync", getSubjectInformationAccess(certificate));
    }

    private static URI findFirstByMethod(ASN1ObjectIdentifier method, String scheme, X509CertificateInformationAccessDescriptor[] accessDescriptor) {
        if (accessDescriptor == null) {
            return null;
        }
        for (X509CertificateInformationAccessDescriptor ad : accessDescriptor) {
            if ((method.equals(ad.getMethod())) && (ad.getLocation().getScheme().equals(scheme))) {
                return ad.getLocation();
            }
        }
        return null;
    }

    public static URI[] getCrlDistributionPoints(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return null;
        }
        try {
            CRLDistPoint crldp = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue));
            return convertCrlDistributionPointToUris(crldp);
        } catch (IOException e) {
            return null;
        }
    }

    private static URI[] convertCrlDistributionPointToUris(CRLDistPoint crldp) {
        List<URI> result = new ArrayList<URI>();
        for (DistributionPoint dp : crldp.getDistributionPoints()) {
            GeneralNames names = (GeneralNames) dp.getDistributionPoint().getName();
            for (GeneralName name : names.getNames()) {
                DERIA5String uri = (DERIA5String) name.getName();
                result.add(URI.create(uri.getString()));
            }
        }
        return result.toArray(new URI[result.size()]);
    }

    public static URI findFirstRsyncCrlDistributionPoint(X509Certificate certificate) {
        URI[] crlDistributionPoints = getCrlDistributionPoints(certificate);
        if (crlDistributionPoints == null) {
            return null;
        }
        for (URI uri : crlDistributionPoints) {
            if (uri != null && "rsync".equals(uri.getScheme())) {
                return uri;
            }
        }
        return null;
    }

    public static URI getManifestUri(X509Certificate certificate) {
        return findFirstSubjectInformationAccessByMethod(certificate, X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST);
    }

    public static URI getRepositoryUri(X509Certificate certificate) {
        return findFirstSubjectInformationAccessByMethod(certificate, X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY);
    }

    public static URI getRrdpNotifyUri(X509Certificate certificate) {
        final X509CertificateInformationAccessDescriptor[] sia = getSubjectInformationAccess(certificate);
        URI byHttp = findFirstByMethod(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY, "http", sia);
        if (byHttp != null)
            return byHttp;
        return findFirstByMethod(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY, "https", sia);
    }

    public static boolean isObjectIssuer(X509Certificate certificate) {
        return getManifestUri(certificate) != null;
    }

    public static ValidityPeriod getValidityPeriod(X509Certificate certificate) {
        return new ValidityPeriod(certificate.getNotBefore(), certificate.getNotAfter());
    }

    public static BigInteger getSerialNumber(X509Certificate certificate) {
        return certificate.getSerialNumber();
    }

    public static X500Principal getSubject(X509Certificate certificate) {
        return certificate.getSubjectX500Principal();
    }

    public static X500Principal getIssuer(X509Certificate certificate) {
        return certificate.getIssuerX500Principal();
    }

    public static PublicKey getPublicKey(X509Certificate certificate) {
        return certificate.getPublicKey();
    }

    public static void verify(X509Certificate certificate, PublicKey publicKey) throws InvalidKeyException, SignatureException {
        try {
            certificate.verify(publicKey, DEFAULT_SIGNATURE_PROVIDER);
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static List<String> getAsns(X509Certificate certificate) {
        ResourceExtensionParser parser = new ResourceExtensionParser();
        byte[] asnExtension = certificate.getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId());
        if (asnExtension == null) {
            return Collections.emptyList();
        }
        final IpResourceSet asResources = parser.parseAsIdentifiers(asnExtension);
        final List<String> asns = new ArrayList<>();
        asResources.forEach(a -> asns.add(a.toString()));
        return asns;
    }

}
