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

    private ValidationOptions options = new ValidationOptions();


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

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailIfCmsObjectDoesNotContainAnyCACertificate() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");

        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())
                .withCrl(CRL);

        subject = new ProvisioningCmsObjectValidator(options, builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate()), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        subject.validate(validationResult);

        assertTrue(validationResult.hasFailures());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFaiIfCmsObjectContainsMultipleCACertificate() {
        ValidationResult validationResult = ValidationResult.withLocation("n/a");

        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())
                .withCrl(CRL);

        subject = new ProvisioningCmsObjectValidator(options, builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate()), ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT);
        subject.validate(validationResult);
    }

}
