package net.ripe.rpki.commons.provisioning.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectValidator;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.issue.response.CertificateIssuanceResponsePayloadSerializerTest;
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponsePayloadSerializerTest;
import net.ripe.rpki.commons.provisioning.payload.revocation.response.CertificateRevocationResponsePayloadBuilderSerializerTest;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.Optional;

import static net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectBuilderTest.*;
import static net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadSerializerTest.*;
import static net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadSerializerTest.*;
import static net.ripe.rpki.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayloadSerializerTest.*;
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
        createValidCmsObjectAndWriteItToDisk(ResourceClassListResponsePayloadSerializerTest.TEST_RESOURCE_CLASS_LIST_RESPONSE_PAYLOAD, "resource-class-list-response.cms");

        createValidCmsObjectAndWriteItToDisk(TEST_CERTIFICATE_ISSUANCE_REQUEST_PAYLOAD, "certificate-issuance-request.cms");
        createValidCmsObjectAndWriteItToDisk(CertificateIssuanceResponsePayloadSerializerTest.TEST_CERTIFICATE_ISSUANCE_RESPONSE_PAYLOAD, "certificate-issuance-response.cms");

        createValidCmsObjectAndWriteItToDisk(TEST_CERTIFICATE_REVOCATION_REQUEST_PAYLOAD, "certificate-revocation-request.cms");
        createValidCmsObjectAndWriteItToDisk(CertificateRevocationResponsePayloadBuilderSerializerTest.TEST_CERTIFICATE_REVOCATION_RESPONSE_PAYLOAD, "certificate-revocation-response.cms");
    }

    public void createValidCmsObjectAndWriteItToDisk(AbstractProvisioningPayload payload, String fileName) throws IOException {
        ProvisioningCmsObject resourceClassListQueryCms = createProvisioningCmsObjectForPayload(payload);
        validateCmsObject(resourceClassListQueryCms);
        writeToDisk(fileName, resourceClassListQueryCms.getEncoded());
    }

    public void validateCmsObject(ProvisioningCmsObject resourceClassListQueryCms) {
        ProvisioningCmsObjectValidator validator = new ProvisioningCmsObjectValidator(ValidationOptions.strictValidation(), Optional.empty(), resourceClassListQueryCms, ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        ValidationResult result = ValidationResult.withLocation("n/a");
        validator.validate(result);
        assertTrue(!result.hasFailures());
    }

    private void writeToDisk(String fileName, byte[] encoded) throws IOException {
        File file = new File(outputDirPath + "/" + fileName);
        Files.write(encoded, file);
    }

}
