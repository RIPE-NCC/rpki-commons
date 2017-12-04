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
package net.ripe.rpki.commons.provisioning.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectParser;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import org.bouncycastle.cms.CMSException;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.Set;

import static org.junit.Assert.*;


public class ProcessApnicPdusTest {

    private static final String PATH_TO_TEST_PDUS = "src/test/resources/apnic-interop";

    @Test
    public void apnic_pdu_2011_08_15_1_has_errors() throws IOException, CMSException {
        byte[] encoded = Files.toByteArray(new File(PATH_TO_TEST_PDUS + "/A971C.1"));

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("cms", encoded);
        ValidationResult validationResult = parser.getValidationResult();
        Set<ValidationCheck> failures = validationResult.getFailuresForCurrentLocation();
        assertTrue("Should have 1 failure", failures.size() == 1);
        assertEquals(ValidationString.ONLY_ONE_CRL_ALLOWED, failures.iterator().next().getKey());
    }

    @Test
    public void apnic_pdu_2011_08_15_3_has_errors() throws IOException, CMSException {
        byte[] encoded = Files.toByteArray(new File(PATH_TO_TEST_PDUS + "/A971C.3"));

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("cms", encoded);
        ValidationResult validationResult = parser.getValidationResult();
        Set<ValidationCheck> failures = validationResult.getFailuresForCurrentLocation();
        assertTrue("Should have 1 failure", failures.size() == 1);
        assertEquals(ValidationString.ONLY_ONE_CRL_ALLOWED, failures.iterator().next().getKey());
    }

    @SuppressWarnings("unused")
    private void prettyPrintFailures(ValidationResult validationResult) {
        for (ValidationLocation location : validationResult.getValidatedLocations()) {
            for (ValidationCheck failure : validationResult.getFailures(location)) {
                System.err.println(location + "\t" + failure + "\n");
            }
        }
    }

}
