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
package net.ripe.rpki.commons.provisioning.x509;

import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.security.KeyPair;
import java.util.Arrays;

import static net.ripe.rpki.commons.provisioning.ProvisioningObjectMother.*;
import static org.junit.Assert.*;

public class ProvisioningIdentityCertificateBuilderTest {

    private ProvisioningIdentityCertificateBuilder subject;

    public static final X500Principal SELF_SIGNING_DN = new X500Principal("CN=test");
    public static final KeyPair TEST_IDENTITY_KEYPAIR = TEST_KEY_PAIR;
    public static final KeyPair TEST_IDENTITY_KEYPAIR_2 = TEST_KEY_PAIR_2;
    public static final ProvisioningIdentityCertificate TEST_IDENTITY_CERT = getTestProvisioningIdentityCertificate();
    public static final ProvisioningIdentityCertificate TEST_IDENTITY_CERT_2 = getProvisioningIdentityCertificateForKey2();

    private static ProvisioningIdentityCertificate getTestProvisioningIdentityCertificate() {
        return getTestBuilder(TEST_IDENTITY_KEYPAIR).build();

    }

    private static ProvisioningIdentityCertificate getProvisioningIdentityCertificateForKey2() {
        return getTestBuilder(TEST_IDENTITY_KEYPAIR_2).build();
    }

    private static ProvisioningIdentityCertificateBuilder getTestBuilder(KeyPair keyPair) {
        ProvisioningIdentityCertificateBuilder identityCertificateBuilder = new ProvisioningIdentityCertificateBuilder();
        identityCertificateBuilder.withSelfSigningKeyPair(keyPair);
        identityCertificateBuilder.withSelfSigningSubject(SELF_SIGNING_DN);
        return identityCertificateBuilder;
    }


    @Before
    public void setUp() {
        // Create a builder with all requirements so that we can exclude (nullify) each
        // requirement for easy unit testing of the builder
        subject = getTestBuilder(TEST_IDENTITY_KEYPAIR);
    }

    @Test
    public void shouldBuild() {
        ProvisioningIdentityCertificate identityCert = subject.build();
        assertNotNull(identityCert);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireSelfSigningKeyPair() {
        subject = new ProvisioningIdentityCertificateBuilder();
        subject.withSelfSigningSubject(ProvisioningIdentityCertificateBuilderTest.SELF_SIGNING_DN);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireSelfSigningDN() {
        subject.withSelfSigningSubject(null);
        subject.build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRequireSignatureProvider() {
        subject.withSignatureProvider(null);
        subject.build();
    }


    // ======= the following unit tests test properties of the certificate built by this builder =====

    /**
     * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
     */
    @Test
    public void shouldUseSHA256withRSA() {
        ProvisioningIdentityCertificate identityCert = subject.build();
        assertEquals("SHA256withRSA", identityCert.getCertificate().getSigAlgName());
    }

    @Test
    public void shouldUseProvidedSigningKey() {
        assertEquals(TEST_IDENTITY_KEYPAIR.getPublic(), TEST_IDENTITY_CERT.getPublicKey());
    }

    /**
     * No CRL. These certs are not published.
     */
    @Test
    public void shouldHaveNoRsyncCrlPointer() {
        assertNull(TEST_IDENTITY_CERT.findFirstRsyncCrlDistributionPoint());
    }

    /**
     * Self signed so should NOT have AIA pointer
     */
    @Test
    public void shouldNotHaveAiaPointer() {
        assertNull(TEST_IDENTITY_CERT.getAuthorityInformationAccess());
    }

    /**
     * No SIA. These certs are not published.
     */
    @Test
    public void shouldHaveSiaPointerToDirectoryOnly() {
        assertNull(TEST_IDENTITY_CERT.getSubjectInformationAccess());
    }

    @Test
    public void shouldBeACACertificate() {
        assertTrue(TEST_IDENTITY_CERT.isCa());
    }

    @Test
    public void shouldIncludeKeyUsageBitsCertSignAndCrlCertSign() {
        boolean[] keyUsage = TEST_IDENTITY_CERT.getCertificate().getKeyUsage();
        assertNotNull(keyUsage);
        // For KeyUsage flags order see bouncy castle KeyUsage class
        assertTrue(Arrays.equals(new boolean[]{false, false, false, false, false, true, true, false, false}, keyUsage));
    }
}

