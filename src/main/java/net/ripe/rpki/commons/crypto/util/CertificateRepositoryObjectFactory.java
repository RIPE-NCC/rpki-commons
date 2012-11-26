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
package net.ripe.rpki.commons.crypto.util;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParser;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;

public final class CertificateRepositoryObjectFactory {

    private CertificateRepositoryObjectFactory() {
        //Utility classes should not have a public or default constructor.
    }

    /**
     * @param encoded the DER encoded object.
     * @throws CertificateRepositoryObjectParserException when encoded object can't be parsed
     */
    public static CertificateRepositoryObject createCertificateRepositoryObject(byte[] encoded, ValidationResult validationResult) {
        CertificateRepositoryObject result;

        // Try to parse as resource certificate
        result = tryParseAsX509ResourceCertificate(encoded, validationResult);
        if (result != null) {
            return result;
        }

        // Try to parse as manifest
        result = tryParseAsManifest(encoded, validationResult);
        if (result != null) {
            return result;
        }

        result = tryParseAsCrl(encoded);
        if (result != null) {
            return result;
        }

        // Try to parse as ROA
        result = tryParseAsROA(encoded, validationResult);
        if (result != null) {
            return result;
        }

        throw new CertificateRepositoryObjectParserException("Could not parse encoded object");
    }


    private static CertificateRepositoryObject tryParseAsCrl(byte[] encoded) {
        try {
            return X509Crl.parseDerEncoded(encoded);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static X509ResourceCertificate tryParseAsX509ResourceCertificate(byte[] encoded, ValidationResult validationResult) {
        ValidationResult temp = new ValidationResult();
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser(temp);
        parser.parse(validationResult.getCurrentLocation(), encoded);
        if (parser.isSuccess()) {
            validationResult.addAll(temp);
            return parser.getCertificate();
        } else {
            return null;
        }
    }

    private static RoaCms tryParseAsROA(byte[] encoded, ValidationResult validationResult) {
        ValidationResult temp = new ValidationResult();
        RoaCmsParser parser = new RoaCmsParser(temp);
        parser.parse(validationResult.getCurrentLocation(), encoded);
        if (parser.isSuccess()) {
            validationResult.addAll(temp);
            return parser.getRoaCms();
        } else {
            return null;
        }
    }

    private static ManifestCms tryParseAsManifest(byte[] encoded, ValidationResult validationResult) {
        ValidationResult temp = new ValidationResult();
        ManifestCmsParser parser = new ManifestCmsParser(temp);
        parser.parse(validationResult.getCurrentLocation(), encoded);
        if (parser.isSuccess()) {
            validationResult.addAll(temp);
            return parser.getManifestCms();
        } else {
            return null;
        }
    }
}
