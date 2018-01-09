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

import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionParser;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.ResourceValidatorFactory;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateValidator;
import org.apache.commons.lang.Validate;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Map.Entry;
import java.util.SortedMap;

/**
 * Wraps a X509 certificate containing RFC3779 resource extensions.
 */
public class X509ResourceCertificate extends X509GenericCertificate implements X509CertificateObject {

    private static final long serialVersionUID = 2L;

    private final EnumSet<IpResourceType> inheritedResourceTypes;
    private final IpResourceSet resources;
    private Boolean revoked;


    protected X509ResourceCertificate(X509Certificate certificate) {
        super(certificate);
        ResourceExtensionParser parser = new ResourceExtensionParser();

        inheritedResourceTypes = EnumSet.noneOf(IpResourceType.class);
        resources = new IpResourceSet();

        byte[] ipAddressBlocksExtension = getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS.getId());
        if (ipAddressBlocksExtension != null) {
            SortedMap<AddressFamily, IpResourceSet> ipResources = parser.parseIpAddressBlocks(ipAddressBlocksExtension);
            for (Entry<AddressFamily, IpResourceSet> resourcesByType : ipResources.entrySet()) {
                if (resourcesByType.getValue() == null) {
                    inheritedResourceTypes.add(resourcesByType.getKey().toIpResourceType());
                } else {
                    resources.addAll(resourcesByType.getValue());
                }
            }
        }

        byte[] asnExtension = getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId());
        if (asnExtension != null) {
            IpResourceSet asResources = parser.parseAsIdentifiers(asnExtension);
            if (asResources == null) {
                inheritedResourceTypes.add(IpResourceType.ASN);
            } else {
                resources.addAll(asResources);
            }
        }
        Validate.isTrue(!inheritedResourceTypes.isEmpty() || !resources.isEmpty(), "empty resource set");
    }

    public IpResourceSet getResources() {
        return new IpResourceSet(resources);
    }

    public EnumSet<IpResourceType> getInheritedResourceTypes() {
        return inheritedResourceTypes;
    }

    public boolean isResourceTypesInherited(EnumSet<IpResourceType> resourceTypes) {
        return inheritedResourceTypes.containsAll(resourceTypes);
    }

    public boolean isResourceSetInherited() {
        return !inheritedResourceTypes.isEmpty();
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
        parser.parse(ValidationResult.withLocation(location), getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }

        validator.validate(location, this);
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result) {
        X509Crl crl = null;
        if (!isRoot()) {
            ValidationLocation savedCurrentLocation = result.getCurrentLocation();
            result.setLocation(new ValidationLocation(getCrlUri()));
            crl = crlLocator.getCrl(getCrlUri(), context, result);
            result.setLocation(savedCurrentLocation);
            if (crl == null) {
                result.rejectIfFalse(false, ValidationString.OBJECTS_CRL_VALID, getCrlUri().toString());
                return;
            }
        }
        X509ResourceCertificateValidator validator = ResourceValidatorFactory.getX509ResourceCertificateValidator(context, options, result, crl);
        validator.validate(location, this);

        revoked = hasErrorInRevocationCheck(result.getFailures(new ValidationLocation(location)));
    }

    @Override
    public void validate(String location,
                         CertificateRepositoryObjectValidationContext context,
                         X509Crl crl,
                         URI crlUri,
                         ValidationOptions options,
                         ValidationResult result) {
        if (!isRoot() && crl == null) {
            result.rejectIfFalse(false, ValidationString.OBJECTS_CRL_VALID, crlUri.toString());
            return;
        }
        X509ResourceCertificateValidator validator = ResourceValidatorFactory.getX509ResourceCertificateValidator(context, options, result, crl);
        validator.validate(location, this);

        revoked = hasErrorInRevocationCheck(result.getFailures(new ValidationLocation(location)));

    }

    @Override
    public boolean isPastValidityTime() {
        return getValidityPeriod().isExpiredNow();
    }

    @Override
    public boolean isRevoked() {
        if (revoked == null) {
            throw new IllegalStateException("isRevoked() could only be called after validate()");
        }
        return revoked;
    }

    public IpResourceSet deriveResources(IpResourceSet parentResources) {
        IpResourceSet result = new IpResourceSet(getResources());
        for (IpResource ipResource : parentResources) {
            if (inheritedResourceTypes.contains(ipResource.getType())) {
                result.add(ipResource);
            }
        }
        return result;
    }

}
