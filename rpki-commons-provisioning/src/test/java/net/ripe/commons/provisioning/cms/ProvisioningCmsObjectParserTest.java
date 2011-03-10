package net.ripe.commons.provisioning.cms;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;
import net.ripe.commons.certification.validation.ValidationResult;

import org.bouncycastle.asn1.DEREncodable;
import org.junit.Test;


public class ProvisioningCmsObjectParserTest {


    @Test
    public void shouldParseValidObject() {
        ProvisioningCmsObject cmsObject = ProvisioningCmsObjectBuilderTest.createProvisioningCmsObject();
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser() {
            @Override
            protected void decodeContent(DEREncodable encoded) {
            }
        };
        parser.parseCms(cmsObject.getEncoded());

        ValidationResult validationResult = parser.getValidationResult();
        assertFalse(validationResult.hasFailures());
        assertEquals(cmsObject, parser.getProvisioningCmsObject());
    }

    @Test(expected=ProvisioningCmsObjectParserException.class)
    public void shouldFailOnInvalidObject() {
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser() {
            @Override
            protected void decodeContent(DEREncodable encoded) {
            }
        };
        parser.parseCms(new byte[] {0});

        ValidationResult validationResult = parser.getValidationResult();
        assertTrue(validationResult.hasFailures());
        assertEquals(1, validationResult.getFailuresForCurrentLocation().size());
        assertEquals(CMS_DATA_PARSING, validationResult.getFailuresForCurrentLocation().iterator().next().getKey());

        parser.getProvisioningCmsObject(); // results in an exception
    }
}
