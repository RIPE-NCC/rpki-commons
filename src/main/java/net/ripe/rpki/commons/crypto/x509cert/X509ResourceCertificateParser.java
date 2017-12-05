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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.util.regex.Pattern;

import static net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper.POLICY_OID;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil.findFirstRsyncCrlDistributionPoint;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil.isRoot;
import static net.ripe.rpki.commons.validation.ValidationString.*;


public class X509ResourceCertificateParser extends X509CertificateParser<X509ResourceCertificate> {

    // ASN.1 PrintableString type
    private static final Pattern PRINTABLE_STRING = Pattern.compile("[-A-Za-z0-9 '()+,./:=?]+");

    @Override
    public X509ResourceCertificate getCertificate() {
        if (!isSuccess()) {
            throw new IllegalArgumentException("Resource Certificate validation failed");
        }
        return new X509ResourceCertificate(getX509Certificate());
    }

    @Override
    protected void doTypeSpecificValidation() {
        validateIssuerAndSubjectDN();
        validateCertificatePolicy();
        validateResourceExtensions();
        validateCrlDistributionPoints();
    }

    private void validateIssuerAndSubjectDN() {
        try {
            JcaX509CertificateHolder cert = new JcaX509CertificateHolder(certificate);
            getValidationResult().warnIfFalse(isValidName(cert.getIssuer()), CERT_ISSUER_CORRECT, certificate.getIssuerX500Principal().toString());
            getValidationResult().warnIfFalse(isValidName(cert.getSubject()), CERT_SUBJECT_CORRECT, certificate.getSubjectX500Principal().toString());
        } catch (CertificateEncodingException e) {
            throw new AbstractX509CertificateWrapperException(e);
        }
    }

    private boolean isValidName(X500Name principal) {
        // RCF6487 section 4.4 and 4.5.
        return hasOneValidCn(principal) && mayHaveOneValidSerialNumber(principal);
    }

    public boolean mayHaveOneValidSerialNumber(X500Name principal) {
        RDN[] serialNumbers = principal.getRDNs(BCStyle.SERIALNUMBER);
        return serialNumbers.length <= 1;
    }

    private boolean hasOneValidCn(X500Name principal) {
        RDN[] cns = principal.getRDNs(BCStyle.CN);
        if (cns.length != 1) {
            return false;
        }
        AttributeTypeAndValue firstCn = cns[0].getFirst();
        if (firstCn == null) {
            return false;
        }
        ASN1Encodable firstCnValue = firstCn.getValue();
        return firstCnValue != null && isPrintableString(firstCnValue);
    }

    //http://tools.ietf.org/html/rfc6487#section-4.4
    //CN must be type PrintableString
    private boolean isPrintableString(ASN1Encodable value){
    	return value instanceof DERPrintableString;
    }

    private void validateCertificatePolicy() {
        if (!result.rejectIfNull(certificate.getCriticalExtensionOIDs(), CRITICAL_EXT_PRESENT)) {
            return;
        }

        result.rejectIfFalse(certificate.getCriticalExtensionOIDs().contains(Extension.certificatePolicies.getId()), POLICY_EXT_CRITICAL);

        try {
            byte[] extensionValue = certificate.getExtensionValue(Extension.certificatePolicies.getId());
            if (!result.rejectIfNull(extensionValue, POLICY_EXT_VALUE)) {
                return;
            }
            ASN1Sequence policies = ASN1Sequence.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue));
            if (!result.rejectIfFalse(policies.size() == 1, SINGLE_CERT_POLICY)) {
                return;
            }
            PolicyInformation policy = PolicyInformation.getInstance(policies.getObjectAt(0));

            if (!result.rejectIfNull(policy.getPolicyIdentifier(), POLICY_ID_PRESENT)) {
                return;
            }
            result.rejectIfFalse(POLICY_OID.equals(policy.getPolicyIdentifier()), POLICY_ID_VERSION);
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
            crlDistPoint = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue));
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
                try {
                    URI.create(uri.getString());
                } catch (IllegalArgumentException e) {
                    result.error(CRLDP_URI_SYNTAX);
                    return;
                }
            }
        }
    }
}
