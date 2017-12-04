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
package net.ripe.rpki.commons.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

public class BBNCertificateConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Ignore("Early ripe ncc ta certificates have crldp set")
    @Test
    public void shouldRejectSelfSignedCertificateWithCRLDP() throws IOException {
        // CRLDP is present in the trust anchor 6487#4.8.6
        boolean hasFailure = parseCertificate("badRootBadCRLDP.cer");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldRejectCertificateWithCRLDPWithReasonFieldNotOmitted() throws IOException {
        // CRL Dist Pt has reasons 6487#4.8.6
        boolean hasFailure = parseCertificate("root/badCertCRLDPReasons.cer");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldRejectCertificateWithCRLDPWithCrlIssuer() throws IOException {
        // CRL Dist Pt has CRL Issuer 6487#4.8.6
        boolean hasFailure = parseCertificate("root/badCertCRLDPCrlIssuer.cer");
        assertTrue(hasFailure);
    }

    private boolean parseCertificate(String certificate) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, certificate);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        new X509ResourceCertificateParser().parse(result, encoded);
        return result.hasFailures();
    }
}
