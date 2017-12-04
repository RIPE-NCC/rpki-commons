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
package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObject;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.ResourceValidatorFactory;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateValidator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.net.URI;
import java.util.Collections;
import java.util.List;

public class RoaCms extends RpkiSignedObject implements Roa {

    public static final ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.24");

    private static final long serialVersionUID = 1L;

    private Asn asn;

    private List<RoaPrefix> prefixes;

    protected RoaCms(RpkiSignedObjectInfo cmsObjectInfo, Asn asn, List<RoaPrefix> prefixes) {
        super(cmsObjectInfo);
        this.asn = asn;
        this.prefixes = prefixes;
    }

    @Override
    public Asn getAsn() {
        return asn;
    }

    public IpResourceSet getResources() {
        return getCertificate().getResources();
    }

    @Override
    public List<RoaPrefix> getPrefixes() {
        return Collections.unmodifiableList(prefixes);
    }

    @Override
    public URI getParentCertificateUri() {
        return getCertificate().getParentCertificateUri();
    }

    public static RoaCms parseDerEncoded(byte[] encoded) {
        RoaCmsParser parser = new RoaCmsParser();
        parser.parse(ValidationResult.withLocation("unknown.roa"), encoded);
        return parser.getRoaCms();
    }

    protected void validateWithCrl(String location, CertificateRepositoryObjectValidationContext context, ValidationOptions options, ValidationResult result, X509Crl crl) {
        X509ResourceCertificateValidator validator = ResourceValidatorFactory.getX509ResourceCertificateStrictValidator(context, options, result, crl);
        validator.validate(location, getCertificate());
    }
}
