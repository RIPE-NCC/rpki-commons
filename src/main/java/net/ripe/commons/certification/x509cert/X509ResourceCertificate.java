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

import java.net.URI;
import java.security.cert.X509Certificate;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.rfc3779.ResourceExtensionEncoder;
import net.ripe.commons.certification.rfc3779.ResourceExtensionParser;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateParentChildValidator;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateValidator;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;

/**
 * Wraps a X509 certificate containing RFC3779 resource extensions.
 */
public class X509ResourceCertificate extends AbstractX509CertificateWrapper implements CertificateRepositoryObject {

    private static final long serialVersionUID = 2L;

    private IpResourceSet resources;


    protected X509ResourceCertificate(X509Certificate certificate) {
        super(certificate);
        parseResourceExtensions();
    }

    private void parseResourceExtensions() {
        ResourceExtensionParser parser = new ResourceExtensionParser();
        IpResourceSet result = new IpResourceSet();
        boolean ipInherited = false;
        boolean asInherited = false;
        byte[] ipAddressBlocksExtension = getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS);
        if (ipAddressBlocksExtension != null) {
            IpResourceSet ipResources = parser.parseIpAddressBlocks(ipAddressBlocksExtension);
            if (ipResources == null) {
                ipInherited = true;
            } else {
                result.addAll(ipResources);
            }
        }
        byte[] asnExtension = getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS);
        if (asnExtension != null) {
            IpResourceSet asResources = parser.parseAsIdentifiers(asnExtension);
            if (asResources == null) {
                asInherited = true;
            } else {
                result.addAll(asResources);
            }
        }
        Validate.isTrue(ipInherited == asInherited, "partial inheritance not supported");
        resources = ipInherited && asInherited ? InheritedIpResourceSet.getInstance() : result;
        Validate.isTrue(!resources.isEmpty(), "empty resource set");
    }

    public IpResourceSet getResources() {
        return resources;
    }

    public boolean isResourceSetInherited() {
        return resources instanceof InheritedIpResourceSet;
    }


    public static X509ResourceCertificate parseDerEncoded(byte[] encoded) {
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse("certificate", encoded);
        return parser.getCertificate();
    }
    

    @Override
    public URI getCrlUri() {
        return findFirstRsyncCrlDistributionPoint();
    }

    @Override
    public URI getParentCertificateUri() {
        return findFirstAuthorityInformationAccessByMethod(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS);
    }
    
    public void validate(String location, X509ResourceCertificateValidator validator) {
        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse(location, getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }

        validator.validate(location, this);
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationResult result) {
        X509Crl crl = null;
        if (!isRoot()) {
            ValidationLocation savedCurrentLocation = result.getCurrentLocation();
            result.setLocation(new ValidationLocation(getCrlUri()));
            crl = crlLocator.getCrl(getCrlUri(), context, result);
            result.setLocation(savedCurrentLocation);
            result.rejectIfNull(crl, ValidationString.OBJECTS_CRL_VALID, getCrlUri());
            if (crl == null) {
                return;
            }
        }
        X509ResourceCertificateValidator validator = new X509ResourceCertificateParentChildValidator(result, context.getCertificate(), crl, context.getResources());
        validator.validate(location, this);
    }

}
