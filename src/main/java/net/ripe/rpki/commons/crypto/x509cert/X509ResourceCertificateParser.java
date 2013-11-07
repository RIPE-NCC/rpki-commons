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
package net.ripe.rpki.commons.crypto.x509cert;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.regex.Pattern;

import static net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil.*;
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
        validateResourceExtensionsForResourceCertificates();
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
        return firstCnValue != null && isPrintableString(firstCnValue.toString());
    }

    private boolean isPrintableString(String s) {
        return PRINTABLE_STRING.matcher(s).matches();
    }

    private void validateCertificatePolicy() {
        if (!result.rejectIfNull(certificate.getCriticalExtensionOIDs(), CRITICAL_EXT_PRESENT)) {
            return;
        }

        result.rejectIfFalse(certificate.getCriticalExtensionOIDs().contains(X509Extension.certificatePolicies.getId()), POLICY_EXT_CRITICAL);

        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extension.certificatePolicies.getId());
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

    private void validateResourceExtensionsForResourceCertificates() {
        if (result.rejectIfFalse(isResourceExtensionPresent(), RESOURCE_EXT_PRESENT)) {
            result.rejectIfTrue(false, AS_OR_IP_RESOURCE_PRESENT);
        }
    }

    private void validateCrlDistributionPoints() {
        if (isRoot(certificate)) {
            result.rejectIfNotNull(getCrlDistributionPoints(certificate), CRLDP_OMITTED);
        } else {
           result.rejectIfNull(getCrlDistributionPoints(certificate), CRLDP_PRESENT);
        }
    }
}
