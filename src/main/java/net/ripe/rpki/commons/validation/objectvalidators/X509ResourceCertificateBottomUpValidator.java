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
package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObjectFile;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import static net.ripe.rpki.commons.validation.ValidationString.*;


public class X509ResourceCertificateBottomUpValidator implements X509ResourceCertificateValidator {

    private static final int MAX_CHAIN_LENGTH = 30;
    private X509ResourceCertificate certificate;
    private Collection<X509ResourceCertificate> trustAnchors;
    private ResourceCertificateLocator locator;
    private List<CertificateWithLocation> certificates = new LinkedList<CertificateWithLocation>();
    private ValidationOptions options;
    private ValidationResult result;
    private ValidationLocation location;


    public X509ResourceCertificateBottomUpValidator(ResourceCertificateLocator locator, X509ResourceCertificate... trustAnchors) {
        this(locator, Arrays.asList(trustAnchors));
    }

    public X509ResourceCertificateBottomUpValidator(ResourceCertificateLocator locator, Collection<X509ResourceCertificate> trustAnchors) {
        this(new ValidationOptions(), ValidationResult.withLocation("unknown.cer"), locator, trustAnchors);
    }

    public X509ResourceCertificateBottomUpValidator(ValidationOptions options, ValidationResult result, ResourceCertificateLocator locator, Collection<X509ResourceCertificate> trustAnchors) {
        this.options = options;
        this.result = result;
        this.location = new ValidationLocation("unknown.cer");
        this.locator = locator;
        this.trustAnchors = trustAnchors;
    }

    @Override
    public ValidationResult getValidationResult() {
        return result;
    }

    @Override
    public void validate(String location, X509ResourceCertificate certificate) {
        this.location = new ValidationLocation(location);
        this.certificate = certificate;

        buildCertificationList();
        if (result.hasFailures()) {
            // stop validation: certificate chain too long
            return;
        }

        checkTrustAnchor();

        X509ResourceCertificate parent = certificates.get(0).getCertificate();
        certificates.remove(0); // No need to validate the root (1st parent) certificate against itself

        IpResourceSet resources = parent.getResources();

        for (CertificateWithLocation certificateWithLocation : certificates) {
            String childLocation = certificateWithLocation.getLocation().getName();
            X509ResourceCertificate child = certificateWithLocation.getCertificate();

            X509Crl crl = getCRL(child, result);
            if (result.hasFailures()) {
                // stop validation: crl cannot be parsed
                return;
            }

            X509ResourceCertificateParentChildValidator validator = ResourceValidatorFactory.getX509ResourceCertificateParentChildStrictValidator(options, result, parent, resources, crl);
            validator.validate(childLocation, child);

            resources = child.deriveResources(resources);
            parent = child;
        }
    }

    private void buildCertificationList() {
        certificates.add(0, new CertificateWithLocation(this.certificate, this.location));
        result.setLocation(this.location);
        if (!result.rejectIfFalse(certificates.size() <= MAX_CHAIN_LENGTH, CERT_CHAIN_LENGTH, Integer.valueOf(MAX_CHAIN_LENGTH).toString())) {
            return;
        }

        X509ResourceCertificate cert = this.certificate;
        while (!cert.isRoot()) {
            CertificateRepositoryObjectFile<X509ResourceCertificate> parent = locator.findParent(cert);

            if (!result.rejectIfNull(parent, CERT_CHAIN_COMPLETE)) {
                return;
            }

            X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
            parser.parse(ValidationResult.withLocation(parent.getName()), parent.getContent());
            if (result.hasFailures()) {
                return;
            }

            cert = parser.getCertificate();
            ValidationLocation parentLocation = new ValidationLocation(parent.getName());
            certificates.add(0, new CertificateWithLocation(cert, parentLocation));
            result.setLocation(parentLocation);
            if (!result.rejectIfFalse(certificates.size() <= MAX_CHAIN_LENGTH, CERT_CHAIN_LENGTH, Integer.valueOf(MAX_CHAIN_LENGTH).toString())) {
                return;
            }
        }

    }

    private X509Crl getCRL(X509ResourceCertificate certificate, ValidationResult validationResult) {
        CertificateRepositoryObjectFile<X509Crl> crlFile = locator.findCrl(certificate);
        if (crlFile == null) {
            return null;
        }
        return X509Crl.parseDerEncoded(crlFile.getContent(), validationResult);
    }

    private void checkTrustAnchor() {
        if ((trustAnchors != null) && (trustAnchors.size() > 0)) {
            result.rejectIfFalse(trustAnchors.contains(certificates.get(0).getCertificate()), ROOT_IS_TA);
        }
    }

    private class CertificateWithLocation {

        private final X509ResourceCertificate certificate;
        private final ValidationLocation location;

        public CertificateWithLocation(X509ResourceCertificate certificate, ValidationLocation location) {
            this.location = location;
            this.certificate = certificate;
        }

        public X509ResourceCertificate getCertificate() {
            return certificate;
        }

        public ValidationLocation getLocation() {
            return location;
        }
    }
}
