package net.ripe.commons.provisioning.cms;


import static net.ripe.commons.provisioning.ProvisioningObjectMother.CRL;
import static net.ripe.commons.provisioning.ProvisioningObjectMother.TEST_KEY_PAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Set;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.provisioning.ProvisioningObjectMother;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilder;

import org.junit.Before;
import org.junit.Test;

public class ProvisioningCmsObjectValidatorTest {

    private ProvisioningCmsObjectValidator subject;


    @Before
    public void setUp() throws Exception {
        subject = new ProvisioningCmsObjectValidator(ProvisioningObjectMother.createProvisioningCmsObject(), TEST_IDENTITY_CERT);
    }


    @Test
    public void shouldValidateValidObject() {
        ValidationResult validationResult = new ValidationResult();
        subject.validate(validationResult);

        assertFalse(validationResult.hasFailures());
    }

    @Test
    public void shouldHaveValidatedLocationsForAllObjects() {
        ValidationResult validationResult = new ValidationResult();
        subject.validate(validationResult);

        Set<String> validatedLocations = validationResult.getValidatedLocations();

        assertTrue(validatedLocations.contains("<cms>"));
        assertTrue(validatedLocations.contains("<crl>"));
        assertTrue(validatedLocations.contains("<cms-cert>"));
        assertTrue(validatedLocations.contains("<identity-cert>"));
    }

    @Test
    public void shouldStopIfCmsObjectIsBadlyFormatted() {
        ValidationResult validationResult = new ValidationResult();
        subject = new ProvisioningCmsObjectValidator(new ProvisioningCmsObject(new byte[] {0}, null, null, null, null), TEST_IDENTITY_CERT);
        subject.validate(validationResult);

        assertTrue(validationResult.hasFailures());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldFailIfCmsObjectDoesNotContainAnyCACertificate() {
        ValidationResult validationResult = new ValidationResult();

        ProvisioningCmsObjectBuilder builder =  new ProvisioningCmsObjectBuilder()
                                                        .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                                                        .withCrl(CRL);

        subject = new ProvisioningCmsObjectValidator(builder.build(EE_KEYPAIR.getPrivate()), TEST_IDENTITY_CERT);
        subject.validate(validationResult);

        assertTrue(validationResult.hasFailures());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldFaiIfCmsObjectContainsMultipleCACertificate() {
        ValidationResult validationResult = new ValidationResult();

        ProvisioningCmsObjectBuilder builder =  new ProvisioningCmsObjectBuilder()
                                                        .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                                                        .withCrl(CRL)
                                                        .withCaCertificate(TEST_IDENTITY_CERT.getCertificate(), getProvisioningCertificate().getCertificate());

        subject = new ProvisioningCmsObjectValidator(builder.build(EE_KEYPAIR.getPrivate()), TEST_IDENTITY_CERT);
        subject.validate(validationResult);
    }

    private static ProvisioningIdentityCertificate getProvisioningCertificate() {
        ProvisioningIdentityCertificateBuilder builder = new ProvisioningIdentityCertificateBuilder();
        builder.withSelfSigningKeyPair(TEST_KEY_PAIR);
        builder.withSelfSigningSubject(new X500Principal("CN=test"));
        return builder.build();
    }
}
