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


import org.junit.Test;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class ProvisioningCmsObjectTest {

    @Test
    public void shouldImplementEquals() {
        X509Certificate certificate1 = mock(X509Certificate.class);
        X509CRL crl = mock(X509CRL.class);
        byte[] encodedContent = new byte[]{'f', 'o', 'o'};
        ProvisioningCmsObject cms1 = new ProvisioningCmsObject(encodedContent, certificate1, Collections.<X509Certificate>emptySet(), crl, null);

        assertFalse(cms1.equals(null));
        assertEquals(cms1, cms1);
        assertFalse(cms1.equals("not-the-same-type"));
    }

    @Test
    public void shouldCompareOnlyTheContentForEquality() {
        X509Certificate certificate1 = mock(X509Certificate.class);
        X509Certificate certificate2 = mock(X509Certificate.class);
        X509CRL crl = mock(X509CRL.class);

        byte[] encodedContent = new byte[]{'f', 'o', 'o'};

        ProvisioningCmsObject cms1 = new ProvisioningCmsObject(encodedContent, certificate1, Collections.<X509Certificate>emptySet(), crl, null);
        ProvisioningCmsObject cms2 = new ProvisioningCmsObject(encodedContent, certificate2, Collections.<X509Certificate>emptySet(), crl, null);

        assertEquals(cms1, cms2);
    }

    @Test
    public void shouldUseOnlyTheContentForHashcode() {
        X509Certificate certificate1 = mock(X509Certificate.class);
        X509Certificate certificate2 = mock(X509Certificate.class);
        X509CRL crl = mock(X509CRL.class);

        byte[] encodedContent = new byte[]{'f', 'o', 'o'};

        ProvisioningCmsObject cms1 = new ProvisioningCmsObject(encodedContent, certificate1, Collections.<X509Certificate>emptySet(), crl, null);
        ProvisioningCmsObject cms2 = new ProvisioningCmsObject(encodedContent, certificate2, Collections.<X509Certificate>emptySet(), crl, null);

        assertEquals(cms1.hashCode(), cms2.hashCode());
    }
}
