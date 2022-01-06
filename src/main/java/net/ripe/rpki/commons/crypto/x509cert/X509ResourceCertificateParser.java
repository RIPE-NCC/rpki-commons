package net.ripe.rpki.commons.crypto.x509cert;

import com.google.common.primitives.Booleans;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static net.ripe.rpki.commons.crypto.JavaSecurityConstants.*;
import static net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper.POLICY_OID;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil.findFirstRsyncCrlDistributionPoint;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil.isRoot;
import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.bouncycastle.asn1.x509.PolicyQualifierId.id_qt_cps;


public class X509ResourceCertificateParser extends X509CertificateParser<X509ResourceCertificate> {

    @Override
    public X509ResourceCertificate getCertificate() {
        if (!isSuccess()) {
            throw new IllegalArgumentException(String.format("Resource Certificate validation failed: %s", result.getFailuresForAllLocations()));
        }
        return new X509ResourceCertificate(getX509Certificate());
    }

    @Override
    protected void doTypeSpecificValidation() {
        validateIssuerAndSubjectDN();
        validateKeyUsage();
        validateCertificatePolicy();
        validateResourceExtensions();
        validateCrlDistributionPoints();
        validateSubjectInformationAccess();
    }

    private void validateIssuerAndSubjectDN() {
        X500Name issuer = X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());
        getValidationResult().rejectIfFalse(isValidName(issuer), CERT_ISSUER_CORRECT, certificate.getIssuerX500Principal().toString());
        X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        getValidationResult().rejectIfFalse(isValidName(subject), CERT_SUBJECT_CORRECT, certificate.getSubjectX500Principal().toString());
    }

    /**
     * https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.4
     *
     * KeyUsage validation added as warning to be similar to current checks.
     */
    protected void validateKeyUsage() {
        final boolean[] keyUsage = certificate.getKeyUsage();
        if (!result.rejectIfNull(keyUsage, KEY_USAGE_EXT_PRESENT)) {
            return;
        }

        if (!result.rejectIfFalse(certificate.getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()), KEY_USAGE_EXT_CRITICAL)) {
            return;
        }

        if (X509CertificateUtil.isCa(certificate)) {
            if (result.rejectIfFalse(Booleans.countTrue(keyUsage) == 2, KEY_USAGE_INVALID)) {
                result.rejectIfFalse(keyUsage[KEYCERTSIGN_INDEX], KEY_CERT_SIGN);
                result.rejectIfFalse(keyUsage[CRLSIGN_INDEX], CRL_SIGN);
            }
        } else {
            if (result.rejectIfFalse(Booleans.countTrue(keyUsage) == 1, KEY_USAGE_INVALID)) {
                result.rejectIfFalse(keyUsage[DIG_SIGN_INDEX], DIG_SIGN);
            }
        }
    }

    private boolean isValidName(X500Name principal) {
        // RCF6487 section 4.4 and 4.5.
        return hasOneValidCn(principal) && mayHaveOneValidSerialNumber(principal);
    }

    public boolean mayHaveOneValidSerialNumber(X500Name principal) {
        RDN[] serialNumbers = principal.getRDNs(BCStyle.SERIALNUMBER);
        if (serialNumbers.length == 0) {
            return true;
        }
        return serialNumbers.length == 1 && isPrintableString(serialNumbers[0]);
    }

    private boolean hasOneValidCn(X500Name principal) {
        RDN[] cns = principal.getRDNs(BCStyle.CN);
        return cns.length == 1 && isPrintableString(cns[0]);
    }

    private boolean isPrintableString(RDN rdn) {
        if (rdn.size() != 1) {
            return false;
        }

        AttributeTypeAndValue first = rdn.getFirst();
        ASN1Encodable firstValue = first.getValue();
        // RFC 6487 section 4.4 and 4.5 require PrintableString, but some RPKI objects use UTF-8 string,
        // so accept that as well.
        if (!isPrintableString(firstValue) && !isUTF8String(firstValue)) {
            return false;
        }

        String value = firstValue.toString();
        return DERPrintableString.isPrintableString(value);
    }

    //http://tools.ietf.org/html/rfc6487#section-4.4
    //CN must be type PrintableString
    private boolean isPrintableString(ASN1Encodable value){
    	return value instanceof DERPrintableString;
    }

    private boolean isUTF8String(ASN1Encodable value) {
        return value instanceof DERUTF8String;
    }

    private void validateCertificatePolicy() {
        Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
        if (!result.rejectIfNull(criticalExtensionOIDs, CRITICAL_EXT_PRESENT)) {
            return;
        }

        // https://tools.ietf.org/html/rfc6487#section-4.8.9
        // Certificate Policies - This extension MUST be present and MUST be marked critical.
        result.rejectIfFalse(criticalExtensionOIDs.contains(Extension.certificatePolicies.getId()), POLICY_EXT_CRITICAL);

        try {
            byte[] extensionValue = certificate.getExtensionValue(Extension.certificatePolicies.getId());
            if (!result.rejectIfNull(extensionValue, POLICY_EXT_VALUE)) {
                return;
            }
            // https://tools.ietf.org/html/rfc6487#section-4.8.9
            // It MUST include exactly one policy, as specified in the RPKI CP [RFC6484]
            ASN1Sequence policies = ASN1Sequence.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extensionValue));
            if (!result.rejectIfFalse(policies.size() == 1, SINGLE_CERT_POLICY)) {
                return;
            }
            PolicyInformation policy = PolicyInformation.getInstance(policies.getObjectAt(0));

            if (!result.rejectIfNull(policy.getPolicyIdentifier(), POLICY_ID_PRESENT)) {
                return;
            }
            result.rejectIfFalse(POLICY_OID.equals(policy.getPolicyIdentifier()), POLICY_ID_VERSION);

            // https://tools.ietf.org/html/rfc7318#section-2
            // [RFC6484].  Exactly one policy qualifier MAY be included.
            ASN1Sequence qualifiers = policy.getPolicyQualifiers();
            if (qualifiers != null) {
                result.warnIfFalse(qualifiers.size() <= 1, POLICY_QUALIFIER_NUMBER);

                // If a policy qualifier is included, the policyQualifierId MUST be the
                // Certification Practice Statement (CPS) pointer qualifier type (id-qt-cps).
                if (qualifiers.size() == 1) {
                    PolicyQualifierInfo policyQualifierInfo = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(0));
                    result.warnIfFalse(id_qt_cps.equals(policyQualifierInfo.getPolicyQualifierId()), POLICY_QUALIFIER_TYPE);
                }
            }
        } catch (IOException e) {
            result.rejectIfFalse(false, POLICY_VALIDATION);
        }
    }

    private void validateResourceExtensions() {
        if (result.rejectIfFalse(isResourceExtensionPresent(), RESOURCE_EXT_PRESENT)) {
            result.rejectIfTrue(false, AS_OR_IP_RESOURCE_PRESENT);
        }
    }

    private void validateCrlDistributionPoints() {
        byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

        if (isRoot(certificate)) {
            // early ripe ncc ta certificates have crldp set so for now only warn here
            result.warnIfNotNull(extensionValue, CRLDP_OMITTED);
            return;
        } else {
            if (!result.rejectIfNull(extensionValue, CRLDP_PRESENT)) {
                return;
            }
        }

        CRLDistPoint crlDistPoint;
        try {
            crlDistPoint = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extensionValue));
            result.pass(CRLDP_EXTENSION_PARSED);
        } catch (IOException e) {
            result.error(CRLDP_EXTENSION_PARSED);
            return;
        }
        testCrlDistributionPointsToUrisConversion(crlDistPoint);

        if (!result.hasFailureForCurrentLocation()) {
            result.rejectIfNull(findFirstRsyncCrlDistributionPoint(certificate), CRLDP_RSYNC_URI_PRESENT);
        }
    }

    private void testCrlDistributionPointsToUrisConversion(CRLDistPoint crldp) {
        for (DistributionPoint dp : crldp.getDistributionPoints()) {
            result.rejectIfNotNull(dp.getCRLIssuer(), CRLDP_ISSUER_OMITTED);
            result.rejectIfNotNull(dp.getReasons(), CRLDP_REASONS_OMITTED);
            if (!result.rejectIfNull(dp.getDistributionPoint(), CRLDP_PRESENT)) {
                return;
            }
            if (!result.rejectIfFalse(dp.getDistributionPoint().getType() == DistributionPointName.FULL_NAME, CRLDP_TYPE_FULL_NAME)) {
                return;
            }

            GeneralNames names = (GeneralNames) dp.getDistributionPoint().getName();
            for (GeneralName name : names.getNames()) {
                if (!result.rejectIfFalse(name.getTagNo() == GeneralName.uniformResourceIdentifier, CRLDP_NAME_IS_A_URI)) {
                    return;
                }
                DERIA5String uri = (DERIA5String) name.getName();
                validateURI(uri.toString(), CRLDP_URI_SYNTAX);
            }
        }
    }

    // See https://tools.ietf.org/html/rfc6487#section-4.8.8
    // https://tools.ietf.org/html/rfc8182#section-3.2
    private void validateSubjectInformationAccess() {
        Set<String> nonCriticalExtensionOIDs = certificate.getNonCriticalExtensionOIDs();
        if (!result.rejectIfNull(nonCriticalExtensionOIDs, NON_CRITICAL_EXT_PRESENT)) {
            return;
        }

        result.rejectIfFalse(nonCriticalExtensionOIDs.contains(Extension.subjectInfoAccess.getId()), CERT_SIA_NON_CRITICAL_EXTENSION);

        byte[] extensionValue = certificate.getExtensionValue(Extension.subjectInfoAccess.getId());
        if (!result.rejectIfNull(extensionValue, CERT_SIA_IS_PRESENT)) {
            return;
        }

        List<AccessDescription> accessDescriptors = new ArrayList<>();
        try {
            ASN1Sequence sia = ASN1Sequence.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extensionValue));
            for (ASN1Encodable encodable : sia) {
                accessDescriptors.add(AccessDescription.getInstance(encodable));
            }
            result.pass(CERT_SIA_PARSED);
        } catch (IllegalArgumentException | IOException e) {
            result.error(CERT_SIA_PARSED);
            return;
        }

        if (X509CertificateUtil.isCa(certificate)) {
            validateSiaForCaCertificate(accessDescriptors);
        } else {
            validateSiaForEeCertificate(accessDescriptors);
        }
    }

    // https://tools.ietf.org/html/rfc6487#section-4.8.8.1
    // https://tools.ietf.org/html/rfc8182#section-3.2
    private void validateSiaForCaCertificate(List<AccessDescription> accessDescriptors) {
        boolean hasCaRepositorySia = false;
        boolean hasRsyncRepositoryUri = false;
        boolean hasManifestUri = false;
        for (AccessDescription descriptor : accessDescriptors) {
            if (ID_AD_CA_REPOSITORY.equals(descriptor.getAccessMethod())) {
                hasCaRepositorySia = true;
                URI location = toUri(descriptor, CERT_SIA_URI_SYNTAX);
                if (location != null && "rsync".equalsIgnoreCase(location.getScheme())) {
                    hasRsyncRepositoryUri = true;
                }
            } else if (ID_AD_RPKI_MANIFEST.equals(descriptor.getAccessMethod())) {
                URI location = toUri(descriptor, CERT_SIA_URI_SYNTAX);
                if (location != null && "rsync".equalsIgnoreCase(location.getScheme())) {
                    hasManifestUri = true;
                }
            } else if (ID_AD_RPKI_NOTIFY.equals(descriptor.getAccessMethod())) {
                URI location = toUri(descriptor, CERT_SIA_URI_SYNTAX);
                result.rejectIfFalse(
                        location != null && "https".equalsIgnoreCase(location.getScheme()),
                        CERT_SIA_RRDP_NOTIFY_URI_HTTPS,
                        String.valueOf(descriptor.getAccessLocation())
                );
            }
        }

        result.rejectIfFalse(hasCaRepositorySia, CERT_SIA_CA_REPOSITORY_URI_PRESENT);
        result.rejectIfFalse(hasRsyncRepositoryUri, CERT_SIA_CA_REPOSITORY_RSYNC_URI_PRESENT);
        result.rejectIfFalse(hasManifestUri, CERT_SIA_MANIFEST_URI_PRESENT);
    }

    // https://tools.ietf.org/html/rfc6487#section-4.8.8.2
    private void validateSiaForEeCertificate(List<AccessDescription> accessDescriptors) {
        Set<String> otherAccessMethods = new TreeSet<>();
        boolean hasSignedObjectUri = false;
        for (AccessDescription descriptor : accessDescriptors) {
            if (ID_AD_SIGNED_OBJECT.equals(descriptor.getAccessMethod())) {
                URI location = toUri(descriptor, CERT_SIA_URI_SYNTAX);
                if (location != null && "rsync".equalsIgnoreCase(location.getScheme())) {
                    hasSignedObjectUri = true;
                }
            } else if (ID_AD_RPKI_NOTIFY.equals(descriptor.getAccessMethod())) {
                // RFC 8181 section 3.2 (https://tools.ietf.org/html/rfc8182#section-3.2) says all resource certificates
                // issued by an RRDP using CA must include this access methods. This is in direct contradiction to
                // RFC 6487 section 4.8.8.2. The intention was to only require this for CA certificates, not EE
                // certificates. Since the wording is unclear we'll accept this for now. In the future we might warn.
                URI location = toUri(descriptor, CERT_SIA_URI_SYNTAX);
                result.rejectIfFalse(
                        location != null && "https".equalsIgnoreCase(location.getScheme()),
                        CERT_SIA_RRDP_NOTIFY_URI_HTTPS,
                        String.valueOf(descriptor.getAccessLocation())
                );
            } else {
                otherAccessMethods.add(descriptor.getAccessMethod().getId());
            }
        }

        result.rejectIfFalse(hasSignedObjectUri, CERT_SIA_SIGNED_OBJECT_URI_PRESENT);
        result.rejectIfFalse(otherAccessMethods.isEmpty(), CERT_SIA_EE_CERTIFICATE_OTHER_ACCESS_METHODS, String.join(", ", otherAccessMethods));
    }

    private URI toUri(AccessDescription descriptor, String key) {
        GeneralName location = descriptor.getAccessLocation();
        if (location.getTagNo() != GeneralName.uniformResourceIdentifier) {
            return null;
        }

        return validateURI(location.getName().toString(), key);
    }

    private URI validateURI(String uriString, String key) {
        try {
            URI uri = new URI(uriString);
            URI normalized = uri.normalize();
            if (uri.isOpaque() || !uri.isAbsolute() || uri.getHost() == null) {
                result.error(key, uriString);
            } else if (!uri.equals(normalized)) {
                result.warn(key, uriString);
            } else {
                result.pass(key, uriString);
            }
            return normalized;
        } catch (URISyntaxException e) {
            result.error(key, uriString);
            return null;
        }
    }
}
