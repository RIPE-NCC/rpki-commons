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
package net.ripe.commons.certification.validation;

import com.gargoylesoftware.base.testing.EqualsTester;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;
import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;


public class CertificateRepositoryObjectValidationContextTest {

    private static final IpResourceSet CHILD_RESOURCE_SET = IpResourceSet.parse("10.8.0.0/16");

    private static URI location = URI.create("rsync://host/path");
    private static X509ResourceCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
    private static URI childLocation = URI.create("rsync://host/path/child");

    private CertificateRepositoryObjectValidationContext subject = create();

    public static CertificateRepositoryObjectValidationContext create() {
        return new CertificateRepositoryObjectValidationContext(location, certificate);
    }

    @Test
    public void shouldContainLocationAndCertificateAndResources() {
        assertSame(location, subject.getLocation());
        assertSame(certificate, subject.getCertificate());
        assertSame(certificate.getResources(), subject.getResources());
    }

    @Test
    public void shouldUpdateResourcesForChildCertificateWithoutInheritedResources() {
        X509ResourceCertificate childCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(CHILD_RESOURCE_SET);
        CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, childCertificate);
        assertEquals(CHILD_RESOURCE_SET, childContext.getResources());
    }

    @Test
    public void shouldNotUpdateResourcesForChildCertificateWithInheritedResources() {
        X509ResourceCertificate childCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(InheritedIpResourceSet.getInstance());
        CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, childCertificate);
        assertEquals(subject.getResources(), childContext.getResources());
    }

    @Test
    public void shouldUpdateLocationAndCertificateForChildCertificate() {
        X509ResourceCertificate childCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(InheritedIpResourceSet.getInstance());
        CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, childCertificate);

        assertSame(childLocation, childContext.getLocation());
        assertSame(childCertificate, childContext.getCertificate());
    }

    @Test
    public void testEquals() {
        CertificateRepositoryObjectValidationContext a = new CertificateRepositoryObjectValidationContext(location, certificate);
        CertificateRepositoryObjectValidationContext b = new CertificateRepositoryObjectValidationContext(location, certificate);
        CertificateRepositoryObjectValidationContext c = new CertificateRepositoryObjectValidationContext(URI.create("rsync://another/uri"), X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(InheritedIpResourceSet.getInstance()));
        CertificateRepositoryObjectValidationContext d = new CertificateRepositoryObjectValidationContext(location, certificate) {};
        new EqualsTester(a, b, c, d);
    }
}
