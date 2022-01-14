package net.ripe.rpki.commons.provisioning.cms;


import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.util.Set;

import static net.ripe.rpki.commons.provisioning.ProvisioningObjectMother.*;
import static org.junit.Assert.*;

public class ProvisioningCmsObjectValidatorTest {

    private ProvisioningCmsObjectValidator subject;

    private ValidationOptions options = ValidationOptions.strictValidation();


    @Before
    public void setUp() throws Exception {
        subject = new ProvisioningCmsObjectValidator(options, ProvisioningObjectMother.createResourceClassListQueryProvisioningCmsObject(), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
    }


    @Test
    public void shouldValidateValidObject() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");
        subject.validate(validationResult);

        assertFalse(validationResult.hasFailures());
    }

    @Test
    public void shouldHaveValidatedLocationsForAllObjects() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");
        subject.validate(validationResult);

        Set<ValidationLocation> validatedLocations = validationResult.getValidatedLocations();

        assertTrue(validatedLocations.contains(new ValidationLocation("<cms>")));
        assertTrue(validatedLocations.contains(new ValidationLocation("<crl>")));
        assertTrue(validatedLocations.contains(new ValidationLocation("<cms-cert>")));
        assertTrue(validatedLocations.contains(new ValidationLocation("<identity-cert>")));
    }

    @Test
    public void shouldStopIfCmsObjectIsBadlyFormatted() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");
        subject = new ProvisioningCmsObjectValidator(options, new ProvisioningCmsObject(new byte[]{0}, null, null, null, null), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        subject.validate(validationResult);

        assertTrue(validationResult.hasFailures());
    }

    @Test(expected = NullPointerException.class)
    public void shouldFailIfCmsObjectDoesNotContainAnyCACertificate() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");

        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())
                .withCrl(CRL);

        subject = new ProvisioningCmsObjectValidator(options, builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate()), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        subject.validate(validationResult);

        assertTrue(validationResult.hasFailures());
    }

    @Test(expected = NullPointerException.class)
    public void shouldFaiIfCmsObjectContainsMultipleCACertificate() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");

        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())
                .withCrl(CRL);

        subject = new ProvisioningCmsObjectValidator(options, builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate()), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        subject.validate(validationResult);
    }

}
