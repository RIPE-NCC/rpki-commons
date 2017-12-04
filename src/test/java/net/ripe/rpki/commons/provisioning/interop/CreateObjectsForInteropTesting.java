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
package net.ripe.rpki.commons.provisioning.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectValidator;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayloadBuilderTest;
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponsePayloadBuilderTest;
import net.ripe.rpki.commons.provisioning.payload.revocation.response.CertificateRevocationResponsePayloadBuilderTest;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectBuilderTest.*;
import static net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadBuilderTest.*;
import static net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilderTest.*;
import static net.ripe.rpki.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayloadBuilderTest.*;
import static org.junit.Assert.*;

public class CreateObjectsForInteropTesting {

    private static final String outputDirPath = "/tmp/provisioning-interop";

    @Before
    public void createOutputDir() {
        File outputDir = new File(outputDirPath);
        outputDir.mkdirs();
    }

    @Test
    public void createObjects() throws IOException {
        writeToDisk("identity-cert.cer", ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT.getEncoded());

        createValidCmsObjectAndWriteItToDisk(TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD, "resource-class-list-query.cms");
        createValidCmsObjectAndWriteItToDisk(ResourceClassListResponsePayloadBuilderTest.TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD, "resource-class-list-response.cms");

        createValidCmsObjectAndWriteItToDisk(TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD, "certificate-issuance-request.cms");
        createValidCmsObjectAndWriteItToDisk(CertificateIssuanceResponsePayloadBuilderTest.TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD, "certificate-issuance-response.cms");

        createValidCmsObjectAndWriteItToDisk(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD, "certificate-revocation-request.cms");
        createValidCmsObjectAndWriteItToDisk(CertificateRevocationResponsePayloadBuilderTest.TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD, "certificate-revocation-response.cms");
    }

    public void createValidCmsObjectAndWriteItToDisk(AbstractProvisioningPayload payload, String fileName) throws IOException {
        ProvisioningCmsObject resourceClassListQueryCms = createProvisioningCmsObjectForPayload(payload);
        validateCmsObject(resourceClassListQueryCms);
        writeToDisk(fileName, resourceClassListQueryCms.getEncoded());
    }

    public void validateCmsObject(ProvisioningCmsObject resourceClassListQueryCms) {
        ProvisioningCmsObjectValidator validator = new ProvisioningCmsObjectValidator(new ValidationOptions(), resourceClassListQueryCms, ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        ValidationResult result = ValidationResult.withLocation("n/a");
        validator.validate(result);
        assertTrue(!result.hasFailures());
    }

    private void writeToDisk(String fileName, byte[] encoded) throws IOException {
        File file = new File(outputDirPath + "/" + fileName);
        Files.write(encoded, file);
    }

}
