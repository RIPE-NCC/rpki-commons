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
package net.ripe.rpki.commons.provisioning.payload.common;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.provisioning.serialization.CertificateUrlListConverter;
import net.ripe.rpki.commons.provisioning.serialization.IpResourceSetProvisioningConverter;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

public class CertificateElementConverter implements Converter {

    private static final String CERT_URL = "cert_url";
    private static final String REQ_RESOURCE_SET_AS = "req_resource_set_as";
    private static final String REQ_RESOURCE_SET_IPV4 = "req_resource_set_ipv4";
    private static final String REQ_RESOURCE_SET_IPV6 = "req_resource_set_ipv6";

    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class type) {
        return type == CertificateElement.class;
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        CertificateElement certificateElement = (CertificateElement) source;

        writer.addAttribute(CERT_URL, CertificateUrlListConverter.INSTANCE.toString(certificateElement.getIssuerCertificatePublicationUris()));
        encodeResources(writer, REQ_RESOURCE_SET_AS, certificateElement.getAllocatedAsn());
        encodeResources(writer, REQ_RESOURCE_SET_IPV4, certificateElement.getAllocatedIpv4());
        encodeResources(writer, REQ_RESOURCE_SET_IPV6, certificateElement.getAllocatedIpv6());
        context.convertAnother(certificateElement.getCertificate().getEncoded());
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        CertificateElement certificateElement = new CertificateElement();

        String uriString = reader.getAttribute(CERT_URL);
        Validate.notNull(uriString, CERT_URL + " attribute is required");
        certificateElement.setIssuerCertificatePublicationLocation(CertificateUrlListConverter.INSTANCE.fromString(uriString));

        certificateElement.setAllocatedAsn(decodeResources(reader, REQ_RESOURCE_SET_AS));
        certificateElement.setAllocatedIpv4(decodeResources(reader, REQ_RESOURCE_SET_IPV4));
        certificateElement.setAllocatedIpv6(decodeResources(reader, REQ_RESOURCE_SET_IPV6));

        certificateElement.setCertificate(decodeCertificate(reader, context));

        return certificateElement;
    }

    private X509ResourceCertificate decodeCertificate(HierarchicalStreamReader reader, UnmarshallingContext context) {
        String encodedCertificate = reader.getValue();
        Validate.notNull(encodedCertificate, "No certificate found");

        byte[] base64DecodedCertificate = (byte[]) context.convertAnother(encodedCertificate.getBytes(), byte[].class);

        X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
        parser.parse(ValidationResult.withLocation("unknown.cer"), base64DecodedCertificate);
        return parser.getCertificate();
    }

    public static IpResourceSet decodeResources(HierarchicalStreamReader reader, String attribute) {
        String resources = reader.getAttribute(attribute);
        if (StringUtils.isBlank(resources)) {
            return null;
        } else {
            return IpResourceSetProvisioningConverter.INSTANCE.fromString(resources);
        }
    }

    public static void encodeResources(HierarchicalStreamWriter writer, String attribute, IpResourceSet resources) {
        if (resources != null && !resources.isEmpty()) {
            writer.addAttribute(attribute, IpResourceSetProvisioningConverter.INSTANCE.toString(resources));
        }
    }
}
