package net.ripe.commons.provisioning.interop;

import static net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilderTest.*;
import static net.ripe.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadBuilderTest.*;
import static net.ripe.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayloadBuilderTest.*;
import static net.ripe.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilderTest.*;
import static net.ripe.commons.provisioning.payload.list.response.ResourceClassListResponsePayloadBuilderTest.*;
import static net.ripe.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayloadBuilderTest.*;
import static net.ripe.commons.provisioning.payload.revocation.response.CertificateRevocationResponsePayloadBuilderTest.*;
import static net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectValidator;
import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;

import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Test;

public class CreateObjectsForInteropTesting {

    private static final String outputDirPath = "/tmp/provisioning-interop";
    
    @Before
    public void createOutputDir() {
        File outputDir = new File(outputDirPath);
        outputDir.mkdirs();
    }
    
    @Test
    public void createObjects() throws IOException {
        writeToDisk("identity-cert.cer", TEST_IDENTITY_CERT.getEncoded());
        
        createValidCmsObjectAndWriteItToDisk(TEST_RESOURCE_CLASS_LIST_QUERY_PAYLOAD, "resource-class-list-query.cms");
        createValidCmsObjectAndWriteItToDisk(TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD, "resource-class-list-response.cms");
        
        createValidCmsObjectAndWriteItToDisk(TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD, "certificate-issuance-request.cms");
        createValidCmsObjectAndWriteItToDisk(TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD, "certificate-issuance-response.cms");
        
        createValidCmsObjectAndWriteItToDisk(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD, "certificate-revocation-request.cms");
        createValidCmsObjectAndWriteItToDisk(TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD, "certificate-revocation-response.cms");
    }

    public void createValidCmsObjectAndWriteItToDisk(AbstractProvisioningPayload payload, String fileName) throws IOException {
        ProvisioningCmsObject resourceClassListQueryCms = createProvisioningCmsObjectForPayload(payload);
        validateCmsObject(resourceClassListQueryCms);
        writeToDisk(fileName, resourceClassListQueryCms.getEncoded());
    }

    public void validateCmsObject(ProvisioningCmsObject resourceClassListQueryCms) {
        ProvisioningCmsObjectValidator validator = new ProvisioningCmsObjectValidator(resourceClassListQueryCms, TEST_IDENTITY_CERT);
        ValidationResult result = new ValidationResult();
        validator.validate(result);
        assertTrue(!result.hasFailures());
    }

    private void writeToDisk(String fileName, byte[] encoded) throws IOException {
        File file = new File(outputDirPath + "/" + fileName);
        FileUtils.writeByteArrayToFile(file, encoded);
    }
    
}
