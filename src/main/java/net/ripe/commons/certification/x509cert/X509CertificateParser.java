/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import net.ripe.commons.certification.rfc3779.ResourceExtensionEncoder;
import net.ripe.commons.certification.validation.ValidationResult;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public abstract class X509CertificateParser<T extends AbstractX509CertificateWrapper> {

    private static final String[] ALLOWED_SIGNATURE_ALGORITHM_OIDS = {
        PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(),
    };

    private byte[] encoded;

    protected X509Certificate certificate;

    protected ValidationResult result;

	private final Class<T> certificateClass;

    protected X509CertificateParser(Class<T> certificateClass, ValidationResult result) {
        this.certificateClass = certificateClass;
		this.result = result;
    }

	public void parse(String location, byte[] encoded) { //NOPMD - ArrayIsStoredDirectly
        this.encoded = encoded;

        result.push(location);

        parse();
        if (!result.hasFailureForLocation(location)) {
            validateSignatureAlgorithm();
            doTypeSpecificValidation();
        }
    }

	protected void doTypeSpecificValidation() {     
    }

    public ValidationResult getValidationResult() {
        return result;
    }

    public abstract T getCertificate();

    protected X509Certificate getX509Certificate() {
        return certificate;
    }

    private void parse() {
        InputStream input = null;
        try {
            input = new ByteArrayInputStream(encoded);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) factory.generateCertificate(input);
        } catch (CertificateException e) {
            certificate = null;
        } finally {
            IOUtils.closeQuietly(input);
        }
        result.notNull(certificate, CERTIFICATE_PARSED);
    }



    private void validateSignatureAlgorithm() {
        result.isTrue(ArrayUtils.contains(ALLOWED_SIGNATURE_ALGORITHM_OIDS, certificate.getSigAlgOID()), CERTIFICATE_SIGNATURE_ALGORITHM);
    }
    
    protected boolean isResourceExtensionPresent() {
        if (certificate.getCriticalExtensionOIDs() == null) {
            return false;
        }

        return certificate.getCriticalExtensionOIDs().contains(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS)
            || certificate.getCriticalExtensionOIDs().contains(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS);
    }


}
