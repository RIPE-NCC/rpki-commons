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
package net.ripe.rpki.commons.provisioning.interop;

import com.google.common.io.BaseEncoding;
import com.google.common.io.Files;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectValidator;
import net.ripe.rpki.commons.provisioning.identity.ChildIdentity;
import net.ripe.rpki.commons.provisioning.identity.ChildIdentitySerializer;
import net.ripe.rpki.commons.provisioning.identity.ParentIdentity;
import net.ripe.rpki.commons.provisioning.identity.ParentIdentitySerializer;
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestParser;
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestParserException;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.commons.validation.ValidationString;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class ProcessIscUpdownPdusTest {

    private static final String PATH_TO_TEST_PDUS = "src/test/resources/isc-interop-updown";

    @Test
    public void shouldParseCertificateIssuanceRequest() throws IOException, RpkiCaCertificateRequestParserException {
        byte[] encoded = Files.toByteArray(new File(PATH_TO_TEST_PDUS + "/pdu.200.der"));
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("cms", encoded);
        ValidationResult validationResult = parser.getValidationResult();
        for (ValidationCheck check : validationResult.getFailures(new ValidationLocation("cms"))) {
            System.err.println("Failure: " + check);
        }
        ProvisioningCmsObject provisioningCmsObject = parser.getProvisioningCmsObject();

        CertificateIssuanceRequestPayload payload = (CertificateIssuanceRequestPayload) provisioningCmsObject.getPayload();

        PKCS10CertificationRequest certificateRequest = payload.getRequestElement().getCertificateRequest();

        RpkiCaCertificateRequestParser rpkiCaCertificateRequestParser = new RpkiCaCertificateRequestParser(certificateRequest);
        assertNotNull(rpkiCaCertificateRequestParser.getCaRepositoryUri());
        assertNotNull(rpkiCaCertificateRequestParser.getManifestUri());
        assertNotNull(rpkiCaCertificateRequestParser.getPublicKey());
    }

    @Test
    public void shouldReadIscChildIdentityXml() throws IOException {
        ProvisioningIdentityCertificate childCert = extractCarolIdentityCert();
        assertNotNull(childCert);
    }

    @Test
    public void shouldReadIscIssuerXml() throws IOException {
        String parentXml = Files.asCharSource(new File(PATH_TO_TEST_PDUS + "/issuer-alice-child-bob-parent.xml"), StandardCharsets.UTF_8).read();
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();
        ParentIdentity parentId = serializer.deserialize(parentXml);
        assertNotNull(parentId);
    }

    public ProvisioningIdentityCertificate extractCarolIdentityCert() throws IOException {
        String childIdXml = Files.asCharSource(new File(PATH_TO_TEST_PDUS + "/carol-child-id.xml"), StandardCharsets.UTF_8).read();
        ChildIdentitySerializer serializer = new ChildIdentitySerializer();
        ChildIdentity childId = serializer.deserialize(childIdXml);
        return childId.getIdentityCertificate();
    }

    @Test
    public void shouldValidateRequest() throws IOException {

        // Note this object expired 30 June 2012. Maybe get a new one sometime?
        byte[] encoded = Files.toByteArray(new File(PATH_TO_TEST_PDUS + "/pdu.200.der"));
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("cms", encoded);
        ProvisioningCmsObject provisioningCmsObject = parser.getProvisioningCmsObject();

        ProvisioningIdentityCertificate childCert = extractCarolIdentityCert();

        ProvisioningCmsObjectValidator validator = new ProvisioningCmsObjectValidator(
            ValidationOptions.backCompatibleRipeNccValidator(), provisioningCmsObject, childCert);
        ValidationResult result = ValidationResult.withLocation("unknown.der");
        validator.validate(result);

        List<ValidationCheck> failures = result.getFailuresForAllLocations();

        assertEquals(2, failures.size());

        assertTrue(failures.contains(new ValidationCheck(ValidationStatus.ERROR, ValidationString.NOT_VALID_AFTER, "2012-06-30T04:08:03.000Z")));
        assertTrue(failures.contains(new ValidationCheck(ValidationStatus.ERROR, ValidationString.NOT_VALID_AFTER, "2012-06-30T04:07:24.000Z")));
    }

    @Test
    public void shouldParseAllIscUpDownMessages() throws IOException {
        String[] files = new String[]{"pdu.170.der", "pdu.171.der", "pdu.172.der", "pdu.173.der", "pdu.180.der", "pdu.183.der", "pdu.184.der",
                "pdu.189.der", "pdu.196.der", "pdu.199.der", "pdu.200.der", "pdu.205.der"};
        for (String fileName : files) {
            byte[] encoded = Files.toByteArray(new File(PATH_TO_TEST_PDUS + "/" + fileName));
            ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
            parser.parseCms("cms", encoded);
            assertFalse(parser.getValidationResult().hasFailures());
        }
    }

    @Test
    public void shouldParseRpkidParentResponseXml() throws IOException {
        String xml = Files.asCharSource(new File(PATH_TO_TEST_PDUS + "/rpkid-parent-response.xml"), StandardCharsets.UTF_8).read();
        ParentIdentitySerializer serializer = new ParentIdentitySerializer();

        ParentIdentity parentId = serializer.deserialize(xml);
        assertNotNull(parentId);
    }

    @Test
    public void shouldParseRpkidMessageFromDeutscheTelekom() throws IOException {
        // dtag-outbound-1.der

        String[] files = new String[]{"dtag-outbound-1.der", "dtag-outbound-9.der"};
        final BaseEncoding decoder = BaseEncoding.base64().withSeparator("\n", 76);

        for (String fileName : files) {

            String base64Encoded = Files.asCharSource(new File(PATH_TO_TEST_PDUS + "/" + fileName), StandardCharsets.UTF_8).read();

            final byte[] encoded = decoder.decode(base64Encoded);

            ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
            parser.parseCms("cms", encoded);
            ValidationResult validationResult = parser.getValidationResult();

            assertFalse(validationResult.hasFailures());
        }
    }
}
