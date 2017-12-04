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
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

public class BBNCrlConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Test
    public void shouldParseCrlWith2CrlNumbers() throws IOException {
        //has 2 CRL numbers 6487#errata
        boolean hasFailure = parseCrl("root/CRL2CRLNums/badCRL2CRLNums.crl");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseCrlWithVersion0() throws IOException {
        // CRL version v1 (integer value 0) 6487#5
        boolean hasFailure = parseCrl("root/CRLVersion0/badCRLVersion0.crl");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseCrlWithVersion2() throws IOException {
        // CRL version v3 (integer value 2) 6487#5
        boolean hasFailure = parseCrl("root/CRLVersion2/badCRLVersion2.crl");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseCrlWithWrongSignatureAlgorithmIdInToBeSigned() throws IOException {
        // wrong signature algorithm ID in toBeSigned 6487#5 6485#2
        boolean hasFailure = parseCrl("root/CRLSigAlgInner/badCRLSigAlgInner.crl");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseCrlWithWrongOuterSignatureAlgorithmId() throws IOException {
        // wrong outer signature algorithm ID 6487#5 6485#2
        boolean hasFailure = parseCrl("root/CRLSigAlgOuter/badCRLSigAlgOuter.crl");
        assertTrue(hasFailure);
    }

    private boolean parseCrl(String crl) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, crl);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        X509Crl.parseDerEncoded(encoded, result);
        return result.hasFailures();
    }
}
