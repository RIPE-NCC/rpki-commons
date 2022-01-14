package net.ripe.rpki.commons.provisioning.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import org.bouncycastle.cms.CMSException;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.Set;

import static org.junit.Assert.*;


public class ProcessApnicPdusTest {

    private static final String PATH_TO_TEST_PDUS = "src/test/resources/apnic-interop";

    @Test
    public void apnic_pdu_2011_08_15_1_has_errors() throws IOException, CMSException {
        byte[] encoded = Files.toByteArray(new File(PATH_TO_TEST_PDUS + "/A971C.1"));

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("cms", encoded);
        ValidationResult validationResult = parser.getValidationResult();
        Set<ValidationCheck> failures = validationResult.getFailuresForCurrentLocation();
        assertTrue("Should have 1 failure", failures.size() == 1);
        assertEquals(ValidationString.ONLY_ONE_CRL_ALLOWED, failures.iterator().next().getKey());
    }

    @Test
    public void apnic_pdu_2011_08_15_3_has_errors() throws IOException, CMSException {
        byte[] encoded = Files.toByteArray(new File(PATH_TO_TEST_PDUS + "/A971C.3"));

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("cms", encoded);
        ValidationResult validationResult = parser.getValidationResult();
        Set<ValidationCheck> failures = validationResult.getFailuresForCurrentLocation();
        assertTrue("Should have 1 failure", failures.size() == 1);
        assertEquals(ValidationString.ONLY_ONE_CRL_ALLOWED, failures.iterator().next().getKey());
    }

    @SuppressWarnings("unused")
    private void prettyPrintFailures(ValidationResult validationResult) {
        for (ValidationLocation location : validationResult.getValidatedLocations()) {
            for (ValidationCheck failure : validationResult.getFailures(location)) {
                System.err.println(location + "\t" + failure + "\n");
            }
        }
    }

}
