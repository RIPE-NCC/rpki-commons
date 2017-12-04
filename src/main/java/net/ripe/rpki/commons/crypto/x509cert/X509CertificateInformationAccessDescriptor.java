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

import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class X509CertificateInformationAccessDescriptor extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final ASN1ObjectIdentifier ID_CA_CA_ISSUERS = AccessDescription.id_ad_caIssuers;

    public static final ASN1ObjectIdentifier ID_AD_CA_REPOSITORY = new ASN1ObjectIdentifier(X509ObjectIdentifiers.id_ad + ".5");

    public static final ASN1ObjectIdentifier ID_AD_SIGNED_OBJECT_REPOSITORY = new ASN1ObjectIdentifier(X509ObjectIdentifiers.id_ad + ".9");

    public static final ASN1ObjectIdentifier ID_AD_SIGNED_OBJECT = new ASN1ObjectIdentifier(X509ObjectIdentifiers.id_ad + ".11");

    public static final ASN1ObjectIdentifier ID_AD_RPKI_MANIFEST = new ASN1ObjectIdentifier(X509ObjectIdentifiers.id_ad + ".10");

    public static final ASN1ObjectIdentifier ID_AD_RPKI_NOTIFY = new ASN1ObjectIdentifier(X509ObjectIdentifiers.id_ad + ".13");

    private String method;
    private URI location;

    private static final Map<ASN1ObjectIdentifier, String> METHOD_STRING_TABLE;

    static {
        Map<ASN1ObjectIdentifier, String> map = new HashMap<ASN1ObjectIdentifier, String>();
        map.put(ID_CA_CA_ISSUERS, "ca issuer");
        map.put(ID_AD_CA_REPOSITORY, "ca repository");
        map.put(ID_AD_SIGNED_OBJECT_REPOSITORY, "signed object repository");
        map.put(ID_AD_SIGNED_OBJECT, "signed object");
        map.put(ID_AD_RPKI_MANIFEST, "manifest");
        METHOD_STRING_TABLE = Collections.unmodifiableMap(map);
    }

    public X509CertificateInformationAccessDescriptor(AccessDescription accessDescription) {
        try {
            Validate.isTrue(accessDescription.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier, "access location is not an URI");
            this.method = accessDescription.getAccessMethod().getId();
            this.location = new URI(accessDescription.getAccessLocation().getName().toString());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public X509CertificateInformationAccessDescriptor(ASN1ObjectIdentifier method, URI location) {
        super();
        this.method = method.getId();
        this.location = location;
    }

    public ASN1ObjectIdentifier getMethod() {
        return new ASN1ObjectIdentifier(method);
    }

    public URI getLocation() {
        return location;
    }

    public static AccessDescription[] convertAccessDescriptors(X509CertificateInformationAccessDescriptor... descriptors) {
        Validate.noNullElements(descriptors);
        AccessDescription[] result = new AccessDescription[descriptors.length];
        for (int i = 0; i < descriptors.length; ++i) {
            result[i] = descriptors[i].toAccessDescription();
        }
        return result;
    }

    private AccessDescription toAccessDescription() {
        return new AccessDescription(getMethod(), new GeneralName(GeneralName.uniformResourceIdentifier, location.toString()));
    }

    public static X509CertificateInformationAccessDescriptor[] convertAccessDescriptors(AccessDescription... accessDescriptions) {
        X509CertificateInformationAccessDescriptor[] result = new X509CertificateInformationAccessDescriptor[accessDescriptions.length];
        for (int i = 0; i < result.length; ++i) {
            result[i] = new X509CertificateInformationAccessDescriptor(accessDescriptions[i]);
        }
        return result;
    }

    public static String methodToString(ASN1ObjectIdentifier method) {
        Validate.notNull(method);
        String result = METHOD_STRING_TABLE.get(method);
        return result == null ? method.toString() : result;
    }

    public static ASN1ObjectIdentifier stringToMethod(String method) {
        Validate.notNull(method);
        for (Map.Entry<ASN1ObjectIdentifier, String> entry : METHOD_STRING_TABLE.entrySet()) {
            if (entry.getValue().equals(method)) {
                return entry.getKey();
            }
        }
        return new ASN1ObjectIdentifier(method);
    }
}
