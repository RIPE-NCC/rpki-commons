package net.ripe.commons.provisioning.interop;

import java.io.File;
import java.io.IOException;

import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.junit.Test;

public class ProcessIscUpdownPdusTest {
    
    private static final String PATH_TO_TEST_PDUS = "src/test/resources/isc-interop-updown";
    
    @Test
    public void shouldParsePdu170() throws IOException {
        byte[] encoded = FileUtils.readFileToByteArray(new File(PATH_TO_TEST_PDUS + "/pdu.200.der"));
        ASN1Object asn1Object = ASN1Object.fromByteArray(encoded);
        System.err.println(ASN1Dump.dumpAsString(asn1Object, true));
        
        System.err.println("-----------------------------------------------");
        System.err.println("-----------------------------------------------");
        System.err.println("-----------------------------------------------");
        
        ProvisioningCmsObject ourVeryOwnRequestCms = ProvisioningObjectMother.createResourceCertificateSignRequestProvisioningCmsObject();
        ASN1Object ourOwnAsn = ASN1Object.fromByteArray(ourVeryOwnRequestCms.getEncoded());
        System.err.println(ASN1Dump.dumpAsString(ourOwnAsn, true));
//        
//        
//        RoaCms roaCms = RoaCmsTest.getRoaCms();
//        ASN1Object ourRoaAsn = ASN1Object.fromByteArray(roaCms.getEncoded());
//        System.err.println(ASN1Dump.dumpAsString(ourRoaAsn, true));
        
//        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
//        parser.parseCms("cms", encoded);
//        ValidationResult validationResult = parser.getValidationResult();
//        for (ValidationCheck check:  validationResult.getFailures("cms")) {
//            System.err.println("Failure: " + check);
//        }
//        ProvisioningCmsObject provisioningCmsObject = parser.getProvisioningCmsObject();
//        
//        AbstractProvisioningPayload payload = provisioningCmsObject.getPayload();
//        System.err.println(payload);
    }

}
