/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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
package net.ripe.rpki.commons.provisioning.identity;


import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.util.Base64;


/**
 * Convert ParentIdentity to/from ISC style XML
 */
public class ParentIdentitySerializer extends IdentitySerializer<ParentIdentity> {

    public ParentIdentitySerializer() {
        super();
    }

    @Override
    public ParentIdentity deserialize(final String xml) {
        try {

            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

            dbf.setNamespaceAware(true);
            final DocumentBuilder db = dbf.newDocumentBuilder();
            final InputSource is = new InputSource();
            is.setCharacterStream(new StringReader(xml));
            final Document doc = db.parse(is);

            final Node root = getElement(doc, "parent_response");

            final String childHandle = getAttributeValue(root, "child_handle");
            final String parentHandle = getAttributeValue(root, "parent_handle");
            final String serviceUri = getAttributeValue(root, "service_uri");

            final String parentBpkiTa = getBpkiElementContent(doc, "parent_bpki_ta");

            final ProvisioningIdentityCertificateParser parser = new ProvisioningIdentityCertificateParser();
            parser.parse(ValidationResult.withLocation("unknown.cer"), Base64.getDecoder().decode(parentBpkiTa));

            return new ParentIdentity(URI.create(serviceUri), parentHandle, childHandle, parser.getCertificate());

        } catch (ParserConfigurationException | SAXException | IOException e) {
            //TODO: make it a checked exception?
            throw new IdentitySerializerException(e);
        }
    }

    @Override
    public String serialize(final ParentIdentity parentIdentity) {
        try {
            final DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();

            final DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();

            final Document document = documentBuilder.newDocument();


            final Element parentResponseElement = document.createElementNS(XMLNS, "parent_response");
            parentResponseElement.setAttribute("child_handle", parentIdentity.getChildHandle());
            parentResponseElement.setAttribute("parent_handle", parentIdentity.getParentHandle());
            parentResponseElement.setAttribute("service_uri", parentIdentity.getUpDownUrl().toString());
            parentResponseElement.setAttribute("version", Integer.toString(parentIdentity.getVersion()));

            final Element parentBpkiTaElement = document.createElementNS(XMLNS, "parent_bpki_ta");
            parentBpkiTaElement.setTextContent(Base64.getEncoder().encodeToString(parentIdentity.getParentIdCertificate().getEncoded()));

            parentResponseElement.appendChild(parentBpkiTaElement);
            document.appendChild(parentResponseElement);

           return toString(document);


        } catch (ParserConfigurationException | TransformerException e) {
            //TODO: make it a checked exception?
            throw new IdentitySerializerException(e);
        }

    }

}
