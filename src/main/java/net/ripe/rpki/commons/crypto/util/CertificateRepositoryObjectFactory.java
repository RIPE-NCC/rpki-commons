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
package net.ripe.rpki.commons.crypto.util;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.UnknownCertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.ghostbuster.GhostbustersCms;
import net.ripe.rpki.commons.crypto.cms.ghostbuster.GhostbustersCmsParser;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParser;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper;
import net.ripe.rpki.commons.crypto.x509cert.X509GenericCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.util.RepositoryObjectType;
import net.ripe.rpki.commons.validation.ValidationChecks;
import net.ripe.rpki.commons.validation.ValidationResult;

public final class CertificateRepositoryObjectFactory {


    private CertificateRepositoryObjectFactory() {
    }

    /**
     * @param encoded the DER encoded object.
     *
     * @return a parsed {@link CertificateRepositoryObject} or {@code null} in case the encoded object has a valid location
     * but its contents can not be parsed.
     */
    public static CertificateRepositoryObject createCertificateRepositoryObject(byte[] encoded, ValidationResult validationResult) {

        RepositoryObjectType objectType = RepositoryObjectType.parse(validationResult.getCurrentLocation().getName());

        ValidationChecks.knownObjectType(objectType, validationResult);

        switch (objectType) {
            case Manifest:
                return parseManifest(encoded, validationResult);
            case Roa:
                return parseRoa(encoded, validationResult);
            case Certificate:
                return parseX509Certificate(encoded, validationResult);
            case Crl:
                return parseCrl(encoded, validationResult);
            case Gbr:
                return parseGbr(encoded, validationResult);
            case Unknown:
                return new UnknownCertificateRepositoryObject(encoded);
            default:
                throw new IllegalArgumentException("Unrecognized repository object type");
        }
    }

    private static X509Crl parseCrl(byte[] encoded, ValidationResult validationResult) {
        return X509Crl.parseDerEncoded(encoded, validationResult);
    }

    private static X509GenericCertificate parseX509Certificate(byte[] encoded, ValidationResult validationResult) {
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        X509GenericCertificate cert = X509ResourceCertificateParser.parseCertificate(temp, encoded);
        validationResult.addAll(temp);
        return cert;
    }

    private static RoaCms parseRoa(byte[] encoded, ValidationResult validationResult) {
        final RoaCmsParser parser = new RoaCmsParser();
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        parser.parse(temp, encoded);
        validationResult.addAll(temp);
        if (parser.isSuccess()) {
            return parser.getRoaCms();
        } else {
            return null;
        }
    }

    private static ManifestCms parseManifest(byte[] encoded, ValidationResult validationResult) {
        final ManifestCmsParser parser = new ManifestCmsParser();
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        parser.parse(temp, encoded);
        if (parser.isSuccess()) {
            validationResult.addAll(temp);
            return parser.getManifestCms();
        } else {
            validationResult.addAll(temp);
            return null;
        }
    }

    private static GhostbustersCms parseGbr(byte[] encoded, ValidationResult validationResult) {
        final GhostbustersCmsParser parser = new GhostbustersCmsParser();
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        parser.parse(temp, encoded);
        if (parser.isSuccess()) {
            validationResult.addAll(temp);
            return parser.getGhostbustersCms();
        } else {
            validationResult.addAll(temp);
            return null;
        }
    }
}
