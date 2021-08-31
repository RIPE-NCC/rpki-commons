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
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.ta.domain.request.ResourceCertificateRequestData;
import net.ripe.rpki.commons.ta.domain.request.RevocationRequest;
import net.ripe.rpki.commons.ta.domain.request.SigningRequest;
import net.ripe.rpki.commons.ta.domain.request.TaRequest;
import net.ripe.rpki.commons.ta.domain.request.TrustAnchorRequest;
import net.ripe.rpki.commons.util.XML;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.UUID;

import static net.ripe.rpki.commons.ta.serializers.Utils.cleanupBase64;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class TrustAnchorRequestSerializerTest {

    private static final String TA_REQUEST_PATH = "src/test/resources/ta/ta-request.xml";
    private static final String LEGACY_TA_REQUEST_PATH = "src/test/resources/ta/legacy-ta-request.xml";
    private static final String TA_REQUEST_NO_TA_URI_PATH = "src/test/resources/ta/ta-request-without-ta-publication-uri.xml";
    public static final java.util.Base64.Encoder BASE64_ENCODER = java.util.Base64.getMimeEncoder(10_000, "\n".getBytes());

    private Document document;
    private final XPath xpath = XPathFactory.newInstance().newXPath();

    private TrustAnchorRequest request;

    @Before
    public void loadState() throws IOException, SAXException, ParserConfigurationException {
        final String stateXML = Files.asCharSource(new File(TA_REQUEST_PATH), Charsets.UTF_8).read();

        final TrustAnchorRequestSerializer trustAnchorRequestSerializer = new TrustAnchorRequestSerializer();
        request = trustAnchorRequestSerializer.deserialize(stateXML);

        DocumentBuilder builder = XML.newNamespaceAwareDocumentBuilder();
        document = builder.parse(new File(TA_REQUEST_PATH));
    }

    /**
     * Evaluate an XPath query and return the result.
     * @param query XPath query
     * @return String result of query
     * @throws XPathExpressionException
     */
    private String xpathQuery(String query) throws XPathExpressionException {
        // No lambda's in Java 6 -> utility function
        return xpath.evaluate(query, document);
    }

    @Test
    public void shouldReadBasicFields() throws XPathExpressionException {
        assertEquals(Long.valueOf(xpathQuery("/requests.TrustAnchorRequest/creationTimestamp")), request.getCreationTimestamp());
        assertEquals(URI.create(xpathQuery("/requests.TrustAnchorRequest/taCertificatePublicationUri")), request.getTaCertificatePublicationUri());
    }

    /**
     * Validate a X509CertificateInformationAccessDescriptor
     */
    private void validateX509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor ciad, Node node) throws XPathExpressionException {
        assertEquals(xpath.evaluate("method", node), ciad.getMethod().toString());
        assertEquals(URI.create(xpath.evaluate("location", node)), ciad.getLocation());
    }

    /**
     *
     */
    private void shouldReadSigningRequest(SigningRequest sr, Node cur) throws XPathExpressionException {
        assertEquals(UUID.fromString(xpath.evaluate("requestId", cur)), sr.getRequestId());

        ResourceCertificateRequestData rcrd = sr.getResourceCertificateRequest();

        assertEquals(cleanupBase64(xpath.evaluate("resourceCertificateRequest/encodedSubjectPublicKey", cur)),
                     Base64.toBase64String(rcrd.getEncodedSubjectPublicKey()));

        assertEquals(xpath.evaluate("resourceCertificateRequest/resourceClassName", cur), rcrd.getResourceClassName());
        assertEquals(xpath.evaluate("resourceCertificateRequest/subjectDN", cur), rcrd.getSubjectDN().getName());

        // Loop over the subjectInformationAccess values
        X509CertificateInformationAccessDescriptor[] sia = rcrd.getSubjectInformationAccess();
        NodeList siaList = (NodeList)xpath.evaluate("resourceCertificateRequest/subjectInformationAccess/X509CertificateInformationAccessDescriptor",
                cur,
                XPathConstants.NODESET);

        assertEquals(siaList.getLength(), sia.length);
        for (int j=0; j < siaList.getLength(); j++) {
            validateX509CertificateInformationAccessDescriptor(sia[j], siaList.item(j));
        }
    }

    @Test
    public void shouldReadTARequests() throws XPathExpressionException {
        List<TaRequest> signingRequests = request.getTaRequests();

        XPath xpath = XPathFactory.newInstance().newXPath();
        NodeList list = (NodeList)xpath.evaluate("/requests.TrustAnchorRequest/taRequests/requests.SigningRequest",
                document,
                XPathConstants.NODESET);

        // Check for equal length + identical values.
        assertEquals(list.getLength(), signingRequests.size());

        for (int i=0; i < list.getLength(); i++) {
            // implicit: instanceof otherwise: ClassCastException.
            shouldReadSigningRequest((SigningRequest)signingRequests.get(i), list.item(i));
        }
    }

    @Test
    public void shouldReadSiaDescriptors() throws XPathExpressionException {
        X509CertificateInformationAccessDescriptor[] siaDescriptors = request.getSiaDescriptors();

        XPath xpath = XPathFactory.newInstance().newXPath();
        NodeList list = (NodeList)xpath.evaluate("/requests.TrustAnchorRequest/siaDescriptors/X509CertificateInformationAccessDescriptor",
                document,
                XPathConstants.NODESET);

        // Check for equal length + identical values.
        assertEquals(list.getLength(), siaDescriptors.length);

        for (int i=0; i < list.getLength(); i++) {
            validateX509CertificateInformationAccessDescriptor(siaDescriptors[i], list.item(i));
        }
    }

    @Test
    public void itShouldDeserializeSigningRequestTaCertificatePublicationUri() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        assertEquals("rsync://localhost:10873/ta/", taRequest.getTaCertificatePublicationUri().toString());
    }

    @Test
    public void itShouldDeserializeSigningRequestCreationTimestamp() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        assertEquals(Long.parseLong("1558700883582"), taRequest.getCreationTimestamp().longValue());
    }

    @Test
    public void itShouldDeserializeSigningRequestTaSigningRequests() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        assertEquals(1, taRequest.getTaRequests().size());

        final TaRequest signingRequest = taRequest.getTaRequests().get(0);
        assertEquals(UUID.fromString("4ee2e78c-f746-426b-bf8b-c37e0155ca3e") ,signingRequest.getRequestId());
    }

    @Test
    public void itShouldDeserializeSigningRequestResourceCertificateRequestInSigningRequest() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(signingRequest);

        final SigningRequest signingRequest = (SigningRequest)taRequest.getTaRequests().get(0);
        final ResourceCertificateRequestData resourceCertificateRequest = signingRequest.getResourceCertificateRequest();
        assertEquals("DEFAULT", resourceCertificateRequest.getResourceClassName());
        assertEquals(new X500Principal("CN=8ecc2cdf3247ef43295ebafca8c711ffd51de071"), resourceCertificateRequest.getSubjectDN());

        final String subjectPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtZC7nbyxIqHdncRCXV6wBtBfXtMjuz0TQLd20Hunnr/982wFMqRfsBqEI4+Q/KnPV+N1rsKGhTrAzOCnISDFO5d111qOrWWd/X0T3AjoBLu2yFwtsc+2PYXxM7aAwPl1YfBsmvDjc+BlZEmPgIVLTbkYW2dXaOKVWi5CHpcbHuzox3stStSF9C2CT49N7URwL5qQ7f55BA4kQ1U1grnQR9nbFWT0HjiVIeZow+9ofRD6Io/T6+sMS2LWb3E+YMK6DCdStlYwmZEu+2HpqBjRqB7/3nfO74djpnUXLMzSFIv4x95ZFAeV0GTvLbflfTRd9G9Wa5CF5hd9zrj5OMNwAwIDAQAB";
        assertEquals(subjectPublicKey, BASE64_ENCODER.encodeToString(resourceCertificateRequest.getEncodedSubjectPublicKey()));

    }

    @Test
    public void itShouldDeserializeSigningRequestSubjectInformationAccessDescriptorsInResourceCertificateRequest() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(signingRequest);

        final SigningRequest signingRequest = (SigningRequest)taRequest.getTaRequests().get(0);
        final ResourceCertificateRequestData resourceCertificateRequest = signingRequest.getResourceCertificateRequest();
        final X509CertificateInformationAccessDescriptor[] subjectInformationAccessDescriptors = resourceCertificateRequest.getSubjectInformationAccess();

        assertEquals(3, subjectInformationAccessDescriptors.length);

        final X509CertificateInformationAccessDescriptor subjectInformationAccess = subjectInformationAccessDescriptors[0];
        assertEquals(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.5"), subjectInformationAccess.getMethod());
        assertEquals(URI.create("rsync://localhost/online/aca/"), subjectInformationAccess.getLocation());
    }

    @Test
    public void itShouldDeserializeSigningRequestSubjectInformationAccessDescriptorsInTrustAnchorRequest() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        final X509CertificateInformationAccessDescriptor[] subjectInformationAccessDescriptors = taRequest.getSiaDescriptors();

        assertEquals(2, subjectInformationAccessDescriptors.length);

        final X509CertificateInformationAccessDescriptor subjectInformationAccess = subjectInformationAccessDescriptors[0];
        assertEquals(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.13"), subjectInformationAccess.getMethod());
        assertEquals(URI.create("http://localhost:7788/notification.xml"), subjectInformationAccess.getLocation());
    }

    @Test
    public void itShouldDeserializeRevocationRequestTaCertificatePublicationUri() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(revocationRequest);
        assertEquals("rsync://localhost:10873/ta/", taRequest.getTaCertificatePublicationUri().toString());
    }

    @Test
    public void itShouldDeserializeRevocationRequestCreationTimestamp() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(revocationRequest);
        assertEquals(Long.parseLong("1610359575105"), taRequest.getCreationTimestamp().longValue());
    }

    @Test
    public void itShouldDeserializeRevocationRequestTaSigningRequests() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(revocationRequest);
        assertEquals(1, taRequest.getTaRequests().size());

        final TaRequest signingRequest = taRequest.getTaRequests().get(0);
        assertEquals(UUID.fromString("3ced3f70-a2b4-42d4-9e46-2fe4cac6b4bf") ,signingRequest.getRequestId());
    }

    @Test
    public void itShouldDeserializeRevocationRequestResourceCertificateRequestInSigningRequest() {
        final TrustAnchorRequest taRequest = new TrustAnchorRequestSerializer().deserialize(revocationRequest);

        final RevocationRequest revocationRequest = (RevocationRequest)taRequest.getTaRequests().get(0);
        assertEquals("DEFAULT", revocationRequest.getResourceClassName());

        final String subjectPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtZC7nbyxIqHdncRCXV6wBtBfXtMjuz0TQLd20Hunnr/982wFMqRfsBqEI4+Q/KnPV+N1rsKGhTrAzOCnISDFO5d111qOrWWd/X0T3AjoBLu2yFwtsc+2PYXxM7aAwPl1YfBsmvDjc+BlZEmPgIVLTbkYW2dXaOKVWi5CHpcbHuzox3stStSF9C2CT49N7URwL5qQ7f55BA4kQ1U1grnQR9nbFWT0HjiVIeZow+9ofRD6Io/T6+sMS2LWb3E+YMK6DCdStlYwmZEu+2HpqBjRqB7/3nfO74djpnUXLMzSFIv4x95ZFAeV0GTvLbflfTRd9G9Wa5CF5hd9zrj5OMNwAwIDAQAB";
        assertEquals(subjectPublicKey,revocationRequest.getEncodedPublicKey());

    }

    @Test
    public void itShouldSerializeSigningRequestTaCertificatePublicationUri() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        assertEquals(taRequest0.getTaCertificatePublicationUri(), taRequest1.getTaCertificatePublicationUri());
    }

    @Test
    public void itShouldSerializeSigningRequestCreationTimestamp() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        assertEquals(taRequest0.getCreationTimestamp(), taRequest1.getCreationTimestamp());
    }

    @Test
    public void itShouldSerializeSigningRequestTaSigningRequests() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        assertEquals(taRequest0.getTaRequests().size(), taRequest1.getTaRequests().size());
        assertEquals(taRequest0.getTaRequests().get(0).getRequestId(), taRequest1.getTaRequests().get(0).getRequestId());

    }

    @Test
    public void itShouldSerializeSigningRequestResourceCertificateRequestInSigningRequest() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        final ResourceCertificateRequestData resourceCertificateRequest0 = ((SigningRequest)taRequest0.getTaRequests().get(0)).getResourceCertificateRequest();
        final ResourceCertificateRequestData resourceCertificateRequest1 = ((SigningRequest)taRequest1.getTaRequests().get(0)).getResourceCertificateRequest();

        assertEquals(resourceCertificateRequest0.getResourceClassName(), resourceCertificateRequest1.getResourceClassName());
        assertEquals(resourceCertificateRequest0.getSubjectDN(), resourceCertificateRequest1.getSubjectDN());
        assertEquals(BASE64_ENCODER.encodeToString(resourceCertificateRequest0.getEncodedSubjectPublicKey()), BASE64_ENCODER.encodeToString(resourceCertificateRequest1.getEncodedSubjectPublicKey()));

    }

    @Test
    public void itShouldSerializeSigningRequestSubjectInformationAccessDescriptorsInResourceCertificateRequest() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        final ResourceCertificateRequestData resourceCertificateRequest0 = ((SigningRequest)taRequest0.getTaRequests().get(0)).getResourceCertificateRequest();
        final ResourceCertificateRequestData resourceCertificateRequest1 = ((SigningRequest)taRequest1.getTaRequests().get(0)).getResourceCertificateRequest();

        final X509CertificateInformationAccessDescriptor[] subjectInformationAccess0 = resourceCertificateRequest0.getSubjectInformationAccess();
        final X509CertificateInformationAccessDescriptor[] subjectInformationAccess1 = resourceCertificateRequest1.getSubjectInformationAccess();

        assertEquals(subjectInformationAccess0.length, subjectInformationAccess1.length);

        final X509CertificateInformationAccessDescriptor x509CertificateInformationAccessDescriptor0 = subjectInformationAccess0[0];
        final X509CertificateInformationAccessDescriptor x509CertificateInformationAccessDescriptor1 = subjectInformationAccess1[0];

        assertEquals(x509CertificateInformationAccessDescriptor0.getMethod(), x509CertificateInformationAccessDescriptor1.getMethod());
        assertEquals(x509CertificateInformationAccessDescriptor0.getLocation(), x509CertificateInformationAccessDescriptor1.getLocation());
    }

    @Test
    public void itShouldSerializeSigningRequestSubjectInformationAccessDescriptorsInTrustAnchorRequest() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(signingRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);


        final X509CertificateInformationAccessDescriptor[] subjectInformationAccess0 = taRequest0.getSiaDescriptors();
        final X509CertificateInformationAccessDescriptor[] subjectInformationAccess1 = taRequest1.getSiaDescriptors();

        assertEquals(subjectInformationAccess0.length, subjectInformationAccess1.length);

        final X509CertificateInformationAccessDescriptor x509CertificateInformationAccessDescriptor0 = subjectInformationAccess0[0];
        final X509CertificateInformationAccessDescriptor x509CertificateInformationAccessDescriptor1 = subjectInformationAccess1[0];

        assertEquals(x509CertificateInformationAccessDescriptor0.getMethod(), x509CertificateInformationAccessDescriptor1.getMethod());
        assertEquals(x509CertificateInformationAccessDescriptor0.getLocation(), x509CertificateInformationAccessDescriptor1.getLocation());
    }


    @Test
    public void itShouldSerializeRevocationRequestTaCertificatePublicationUri() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(revocationRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        assertEquals(taRequest0.getTaCertificatePublicationUri(), taRequest1.getTaCertificatePublicationUri());
    }

    @Test
    public void itShouldSerializeRevocationRequestCreationTimestamp() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(revocationRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        assertEquals(taRequest0.getCreationTimestamp(), taRequest1.getCreationTimestamp());
    }

    @Test
    public void itShouldSerializeRevocationRequestTaSigningRequests() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(revocationRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        assertEquals(taRequest0.getTaRequests().size(), taRequest1.getTaRequests().size());
        assertEquals(taRequest0.getTaRequests().get(0).getRequestId(), taRequest1.getTaRequests().get(0).getRequestId());
    }

    @Test
    public void itShouldSerializeRevocationRequestResourceCertificateRequestInSigningRequest() {
        final TrustAnchorRequest taRequest0 = new TrustAnchorRequestSerializer().deserialize(revocationRequest);
        String request = new TrustAnchorRequestSerializer().serialize(taRequest0);
        final TrustAnchorRequest taRequest1 = new TrustAnchorRequestSerializer().deserialize(request);

        final RevocationRequest revocationRequest0 = (RevocationRequest) taRequest0.getTaRequests().get(0);
        final RevocationRequest revocationRequest1 = (RevocationRequest) taRequest1.getTaRequests().get(0);

        assertEquals(revocationRequest0.getResourceClassName(), revocationRequest1.getResourceClassName());
        assertEquals(revocationRequest0.getEncodedPublicKey(), revocationRequest1.getEncodedPublicKey());

    }

    @Test
    public void itShouldDeserializeLegacyXmlRequestElements() throws IOException {

        final String stateXML = Files.asCharSource(new File(LEGACY_TA_REQUEST_PATH), Charsets.UTF_8).read();

        final TrustAnchorRequestSerializer trustAnchorRequestSerializer = new TrustAnchorRequestSerializer();
        final TrustAnchorRequest trustAnchorRequest = trustAnchorRequestSerializer.deserialize(stateXML);


        assertFalse(trustAnchorRequest.getTaRequests().isEmpty());
        assertEquals(2, trustAnchorRequest.getTaRequests().size());
    }


    @Test
    public void itShouldDeserializeXmlWithoutTaCertificatePublicationUriElement() throws IOException {

        final String stateXML = Files.asCharSource(new File(TA_REQUEST_NO_TA_URI_PATH), Charsets.UTF_8).read();

        final TrustAnchorRequestSerializer trustAnchorRequestSerializer = new TrustAnchorRequestSerializer();
        final TrustAnchorRequest trustAnchorRequest = trustAnchorRequestSerializer.deserialize(stateXML);

        assertNotNull(trustAnchorRequest);

    }

    private final String signingRequest = "<requests.TrustAnchorRequest>\n" +
            "  <creationTimestamp>1558700883582</creationTimestamp>\n" +
            "  <taCertificatePublicationUri>rsync://localhost:10873/ta/</taCertificatePublicationUri>\n" +
            "  <taRequests>\n" +
            "    <requests.SigningRequest>\n" +
            "      <requestId>4ee2e78c-f746-426b-bf8b-c37e0155ca3e</requestId>\n" +
            "      <resourceCertificateRequest>\n" +
            "        <resourceClassName>DEFAULT</resourceClassName>\n" +
            "        <subjectDN>CN=8ecc2cdf3247ef43295ebafca8c711ffd51de071</subjectDN>\n" +
            "        <subjectInformationAccess>\n" +
            "          <X509CertificateInformationAccessDescriptor>\n" +
            "            <method>1.3.6.1.5.5.7.48.5</method>\n" +
            "            <location>rsync://localhost/online/aca/</location>\n" +
            "          </X509CertificateInformationAccessDescriptor>\n" +
            "          <X509CertificateInformationAccessDescriptor>\n" +
            "            <method>1.3.6.1.5.5.7.48.10</method>\n" +
            "            <location>rsync://localhost/online/aca/jsws3zJH70MpXrr8qMcR_9Ud4HE.mft</location>\n" +
            "          </X509CertificateInformationAccessDescriptor>\n" +
            "          <X509CertificateInformationAccessDescriptor>\n" +
            "            <method>1.3.6.1.5.5.7.48.13</method>\n" +
            "            <location>http://localhost:7788/notification.xml</location>\n" +
            "          </X509CertificateInformationAccessDescriptor>\n" +
            "        </subjectInformationAccess>\n" +
            "        <ipResourceSet>10.0.0.0/8, 11.0.0.0/8</ipResourceSet>\n" +
            "        <encodedSubjectPublicKey>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtZC7nbyxIqHdncRCXV6wBtBfXtMjuz0TQLd20Hunnr/982wFMqRfsBqEI4+Q/KnPV+N1rsKGhTrAzOCnISDFO5d111qOrWWd/X0T3AjoBLu2yFwtsc+2PYXxM7aAwPl1YfBsmvDjc+BlZEmPgIVLTbkYW2dXaOKVWi5CHpcbHuzox3stStSF9C2CT49N7URwL5qQ7f55BA4kQ1U1grnQR9nbFWT0HjiVIeZow+9ofRD6Io/T6+sMS2LWb3E+YMK6DCdStlYwmZEu+2HpqBjRqB7/3nfO74djpnUXLMzSFIv4x95ZFAeV0GTvLbflfTRd9G9Wa5CF5hd9zrj5OMNwAwIDAQAB</encodedSubjectPublicKey>\n" +
            "      </resourceCertificateRequest>\n" +
            "    </requests.SigningRequest>\n" +
            "  </taRequests>\n" +
            "  <siaDescriptors>\n" +
            "    <X509CertificateInformationAccessDescriptor>\n" +
            "      <method>1.3.6.1.5.5.7.48.13</method>\n" +
            "      <location>http://localhost:7788/notification.xml</location>\n" +
            "    </X509CertificateInformationAccessDescriptor>\n" +
            "    <X509CertificateInformationAccessDescriptor>\n" +
            "      <method>1.3.6.1.5.5.7.48.5</method>\n" +
            "      <location>rsync://localhost/online/</location>\n" +
            "    </X509CertificateInformationAccessDescriptor>\n" +
            "  </siaDescriptors>\n" +
            "</requests.TrustAnchorRequest>";

    private final String revocationRequest = "<requests.TrustAnchorRequest>\n" +
            "  <creationTimestamp>1610359575105</creationTimestamp>\n" +
            "  <taCertificatePublicationUri>rsync://localhost:10873/ta/</taCertificatePublicationUri>\n" +
            "  <taRequests>\n" +
            "    <requests.RevocationRequest>\n" +
            "      <requestId>3ced3f70-a2b4-42d4-9e46-2fe4cac6b4bf</requestId>\n" +
            "      <resourceClassName>DEFAULT</resourceClassName>\n" +
            "      <encodedPublicKey>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtZC7nbyxIqHdncRCXV6wBtBfXtMjuz0TQLd20Hunnr/982wFMqRfsBqEI4+Q/KnPV+N1rsKGhTrAzOCnISDFO5d111qOrWWd/X0T3AjoBLu2yFwtsc+2PYXxM7aAwPl1YfBsmvDjc+BlZEmPgIVLTbkYW2dXaOKVWi5CHpcbHuzox3stStSF9C2CT49N7URwL5qQ7f55BA4kQ1U1grnQR9nbFWT0HjiVIeZow+9ofRD6Io/T6+sMS2LWb3E+YMK6DCdStlYwmZEu+2HpqBjRqB7/3nfO74djpnUXLMzSFIv4x95ZFAeV0GTvLbflfTRd9G9Wa5CF5hd9zrj5OMNwAwIDAQAB</encodedPublicKey>\n" +
            "    </requests.RevocationRequest>\n" +
            "  </taRequests>\n" +
            "  <siaDescriptors/>\n" +
            "</requests.TrustAnchorRequest>";
}
