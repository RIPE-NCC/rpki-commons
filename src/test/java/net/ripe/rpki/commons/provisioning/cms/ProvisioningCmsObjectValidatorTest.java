package net.ripe.rpki.commons.provisioning.cms;


import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.Set;

import static net.ripe.rpki.commons.provisioning.ProvisioningObjectMother.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class ProvisioningCmsObjectValidatorTest {

    private ProvisioningCmsObjectValidator subject;

    private final ValidationOptions options = ValidationOptions.strictValidation();

    @BeforeEach
    public void setUp() throws Exception {
        subject = new ProvisioningCmsObjectValidator(options, Optional.empty(), ProvisioningObjectMother.createResourceClassListQueryProvisioningCmsObject(), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
    }


    @Test
    public void shouldValidateValidObject() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");
        subject.validate(validationResult);

        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Test
    public void shouldHaveValidatedLocationsForAllObjects() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");
        subject.validate(validationResult);

        Set<ValidationLocation> validatedLocations = validationResult.getValidatedLocations();

        assertThat(validatedLocations).contains(new ValidationLocation("<cms>"));
        assertThat(validatedLocations).contains(new ValidationLocation("<crl>"));
        assertThat(validatedLocations).contains(new ValidationLocation("<cms-cert>"));
        assertThat(validatedLocations).contains(new ValidationLocation("<identity-cert>"));
    }

    @Test
    public void shouldStopIfCmsObjectIsBadlyFormatted() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");
        subject = new ProvisioningCmsObjectValidator(options, Optional.empty(), new ProvisioningCmsObject(new byte[]{0}, null, null, null, null), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        subject.validate(validationResult);

        assertThat(validationResult.hasFailures()).isTrue();
    }

    @Disabled("Test content does not appear to match test name")
    @Test
    public void shouldFailIfCmsObjectDoesNotContainAnyCACertificate() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");

        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())
                .withPayloadContent(new ResourceClassListQueryPayloadBuilder().build())
                .withCrl(CRL);

        subject = new ProvisioningCmsObjectValidator(options, Optional.empty(), builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate()), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        assertThatThrownBy(() -> subject.validate(validationResult))
                .isInstanceOf(NullPointerException.class);
        assertThat(validationResult.hasFailures()).isFalse();
    }

    @Disabled("Test content does not appear to match test name")
    @Test
    public void shouldFaiIfCmsObjectContainsMultipleCACertificate() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");

        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())
                .withPayloadContent(new ResourceClassListQueryPayloadBuilder().build())
                .withCrl(CRL);

        assertThatThrownBy(() ->
                new ProvisioningCmsObjectValidator(options, Optional.empty(), builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate()), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT)
        ).hasCauseInstanceOf(NullPointerException.class);
    }
}
