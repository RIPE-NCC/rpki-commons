package net.ripe.commons.provisioning.cms;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.PayloadMessageType;

import org.junit.Before;
import org.junit.Test;

import static net.ripe.commons.certification.validation.ValidationString.CMS_DATA_PARSING;
import static org.junit.Assert.*;


public class ProvisioningCmsObjectParserTest {

    private ProvisioningCmsObjectParser subject;


    @Before
    public void setUp() {
        subject = new ProvisioningCmsObjectParser();
    }

    @Test
    public void shouldParseValidObject() {
        ProvisioningCmsObject cmsObject = ProvisioningCmsObjectBuilderMother.createProvisioningCmsObject();
        subject.parseCms("test-location", cmsObject.getEncoded());

        AbstractProvisioningPayload payload = subject.getPayload();
        assertEquals(PayloadMessageType.list, payload.getType());

        ValidationResult validationResult = subject.getValidationResult();
        assertFalse(validationResult.hasFailures());
        assertEquals(cmsObject, subject.getProvisioningCmsObject());
    }

    @Test(expected=ProvisioningCmsObjectParserException.class)
    public void shouldFailOnInvalidObject() {
        subject.parseCms("test-location", new byte[] {0});

        ValidationResult validationResult = subject.getValidationResult();
        assertTrue(validationResult.hasFailures());
        assertEquals(1, validationResult.getFailuresForCurrentLocation().size());
        assertEquals(CMS_DATA_PARSING, validationResult.getFailuresForCurrentLocation().iterator().next().getKey());

        subject.getProvisioningCmsObject(); // results in an exception
    }
}
