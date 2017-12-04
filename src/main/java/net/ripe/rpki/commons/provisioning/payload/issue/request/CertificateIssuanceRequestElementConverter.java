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
package net.ripe.rpki.commons.provisioning.payload.issue.request;

import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import net.ripe.rpki.commons.provisioning.payload.common.CertificateElementConverter;
import org.apache.commons.lang.Validate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;

public class CertificateIssuanceRequestElementConverter implements Converter {

    private static final String CLASS_NAME = "class_name";
    private static final String REQ_RESOURCE_SET_AS = "req_resource_set_as";
    private static final String REQ_RESOURCE_SET_IPV4 = "req_resource_set_ipv4";
    private static final String REQ_RESOURCE_SET_IPV6 = "req_resource_set_ipv6";

    @Override
    public boolean canConvert(@SuppressWarnings("rawtypes") Class type) {
        return type == CertificateIssuanceRequestElement.class;
    }

    @Override
    public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
        try {
            CertificateIssuanceRequestElement content = (CertificateIssuanceRequestElement) source;

            writer.addAttribute(CLASS_NAME, content.getClassName());
            CertificateElementConverter.encodeResources(writer, REQ_RESOURCE_SET_AS, content.getAllocatedAsn());
            CertificateElementConverter.encodeResources(writer, REQ_RESOURCE_SET_IPV4, content.getAllocatedIpv4());
            CertificateElementConverter.encodeResources(writer, REQ_RESOURCE_SET_IPV6, content.getAllocatedIpv6());
            context.convertAnother(content.getCertificateRequest().getEncoded());
        } catch (IOException e) {
            throw new ConversionException(e);
        }
    }

    @Override
    public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
        try {
            CertificateIssuanceRequestElement content = new CertificateIssuanceRequestElement();

            String className = reader.getAttribute(CLASS_NAME);
            Validate.notNull(className, "class_name attribute is required");
            content.setClassName(className);

            content.setAllocatedAsn(CertificateElementConverter.decodeResources(reader, REQ_RESOURCE_SET_AS));
            content.setAllocatedIpv4(CertificateElementConverter.decodeResources(reader, REQ_RESOURCE_SET_IPV4));
            content.setAllocatedIpv6(CertificateElementConverter.decodeResources(reader, REQ_RESOURCE_SET_IPV6));

            content.setCertificateRequest(decodeCertificateRequest(reader, context));

            return content;
        } catch (IOException e) {
            throw new ConversionException(e);
        }
    }

    private PKCS10CertificationRequest decodeCertificateRequest(HierarchicalStreamReader reader, UnmarshallingContext context) throws IOException {
        String encodedCertificate = reader.getValue();
        Validate.notNull(encodedCertificate, "No certificate found");

        byte[] base64DecodedCertificate = (byte[]) context.convertAnother(encodedCertificate.getBytes(), byte[].class);

        return new PKCS10CertificationRequest(base64DecodedCertificate);
    }

}
