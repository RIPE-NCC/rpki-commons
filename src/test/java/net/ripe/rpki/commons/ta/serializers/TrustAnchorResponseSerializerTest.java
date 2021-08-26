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
package net.ripe.rpki.commons.ta.serializers;


import com.google.common.base.Charsets;
import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateObject;
import net.ripe.rpki.commons.ta.domain.response.TaResponse;
import net.ripe.rpki.commons.ta.domain.response.TrustAnchorResponse;
import net.ripe.rpki.commons.ta.domain.response.SigningResponse;
import net.ripe.rpki.commons.util.XML;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TrustAnchorResponseSerializerTest {
    private static final String TA_RESPONSE_PATH = "src/test/resources/ta/ta-response.xml";

    private Document document;
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    private TrustAnchorResponse response;


    @Before
    public void loadState() throws IOException, SAXException, ParserConfigurationException {
        final String responseXML = Files.asCharSource(new File(TA_RESPONSE_PATH), Charsets.UTF_8).read();

        final TrustAnchorResponseSerializer trustAnchorResponseSerializer = new TrustAnchorResponseSerializer();
        response = trustAnchorResponseSerializer.deserialize(responseXML);

        DocumentBuilder builder = XML.newSecureDocumentBuilder();
        document = builder.parse(new File(TA_RESPONSE_PATH));
    }

    @Test
    public void shouldMatchSimpleFields() throws XPathExpressionException {
        assertEquals(Long.valueOf(xpath.evaluate("/TrustAnchorResponse/requestCreationTimestamp", document)),
            response.getRequestCreationTimestamp());
    }

    @Test
    public void shouldMatchTAResponseField() throws XPathExpressionException, URISyntaxException {
        List<TaResponse> taResponses = response.getTaResponses();

        XPathExpression query = xpath.compile("/TrustAnchorResponse/taResponses/SigningResponse");
        NodeList nodeList = (NodeList) query.evaluate(document, XPathConstants.NODESET);

        // Check for equal length + identical values.
        // Implictly checks that all items are of required type.
        assertEquals(nodeList.getLength(), taResponses.size());

        for (int i = 0; i < nodeList.getLength(); i++) {
            SigningResponse sr = (SigningResponse) taResponses.get(i);
            Node cur = nodeList.item(i);

            assertEquals(UUID.fromString(xpath.evaluate("requestId", cur)), sr.getRequestId());

            assertEquals(xpath.evaluate("resourceClassName", cur), sr.getResourceClassName());
            assertEquals(new URI(xpath.evaluate("publicationUri", cur)), sr.getPublicationUri());
            assertEquals(Utils.cleanupBase64(xpath.evaluate("certificate/encoded", cur)),
                Base64.toBase64String(sr.getCertificate().getEncoded()));
        }
    }

    /**
     * Check the map by getting all the entries from the XML and comparing them to the object.
     * @throws XPathExpressionException
     */
    @Test
    public void shouldMatchPublishedObjects() throws XPathExpressionException, URISyntaxException {
        NodeList entries = (NodeList) xpath.evaluate("/TrustAnchorResponse/publishedObjects/entry",
            document, XPathConstants.NODESET);

        assertEquals(entries.getLength(), response.getPublishedObjects().size());

        for (int i = 0; i < entries.getLength(); i++) {
            Node entry = entries.item(i);

            URI entryURI = new URI(xpath.evaluate("uri", entry));

            CertificateRepositoryObject publishedObject = response.getPublishedObjects().get(entryURI);
            // CertificateRepositoryObject is implemeneted by multiple types.
            String encodedCertificate = xpath.evaluate("X509ResourceCertificate/encoded", entry);
            if (StringUtils.isEmpty(encodedCertificate)) {
                assertFalse(publishedObject instanceof X509CertificateObject);
            } else {
                assertTrue(publishedObject instanceof X509CertificateObject);

                X509CertificateObject xco = (X509CertificateObject) publishedObject;
                assertEquals(Utils.cleanupBase64(encodedCertificate), Base64.toBase64String(xco.getEncoded()));
            }

            String encodedCrl = xpath.evaluate("CRL/encoded", entry);
            if (StringUtils.isEmpty(encodedCrl)) {
                assertFalse(publishedObject instanceof X509Crl);
            } else {
                assertTrue(publishedObject instanceof X509Crl);
                X509Crl crl = (X509Crl) publishedObject;

                assertEquals(Utils.cleanupBase64(encodedCrl), Base64.toBase64String(crl.getEncoded()));
            }

            String encodedManifest = xpath.evaluate("Manifest/encoded", entry);
            if (StringUtils.isEmpty(encodedManifest)) {
                assertFalse(publishedObject instanceof ManifestCms);
            } else {
                assertTrue(publishedObject instanceof ManifestCms);
                ManifestCms mfs = (ManifestCms) publishedObject;

                assertEquals(Utils.cleanupBase64(encodedManifest), Base64.toBase64String(mfs.getEncoded()));
            }
        }
    }

    @Test
    public void shouldSerialiseAndDeserialise() throws IOException {
        final String responseXML = Files.asCharSource(new File(TA_RESPONSE_PATH), Charsets.UTF_8).read();

        final TrustAnchorResponseSerializer trustAnchorResponseSerializer = new TrustAnchorResponseSerializer();
        TrustAnchorResponse response = trustAnchorResponseSerializer.deserialize(responseXML);

        String responseXML2 = trustAnchorResponseSerializer.serialize(response);
        TrustAnchorResponse response1 = trustAnchorResponseSerializer.deserialize(responseXML2);
        assertEquals(response1, response);
    }

}
