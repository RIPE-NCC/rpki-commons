/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
        subject = new ProvisioningCmsObjectValidator(ProvisioningObjectMother.createResourceClassListQueryProvisioningCmsObject(), TEST_IDENTITY_CERT);
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
