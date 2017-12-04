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
package net.ripe.rpki.commons.validation.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParser;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;

public class BBNConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Test
    public void shouldParseAllObjects() throws IOException {
        int objectCount = 0;
        int errorCount = 0;
        int exceptionCount = 0;

        Iterator<File> fileIterator = FileUtils.iterateFiles(new File(PATH_TO_BBN_OBJECTS), new String[]{"cer", "crl", "mft", "roa"}, true);
        while (fileIterator.hasNext()) {
            objectCount++;
            File file = fileIterator.next();
            byte[] encoded = Files.toByteArray(file);
            ValidationResult result = ValidationResult.withLocation(file.getName());

            try {
                if (file.getName().endsWith("cer")) {
                    new X509ResourceCertificateParser().parse(result, encoded);
                } else if (file.getName().endsWith("crl")) {
                    X509Crl.parseDerEncoded(encoded, result);
                } else if (file.getName().endsWith("mft")) {
                    new ManifestCmsParser().parse(result, encoded);
                } else if (file.getName().endsWith("roa")) {
                    new RoaCmsParser().parse(result, encoded);
                }

                if (result.hasFailures() && file.getName().startsWith("good")) {
                    System.err.println("Supposed to be good: " + file.getName());
                    errorCount++;
                } else if (! result.hasFailures() && file.getName().startsWith("bad")) {
                    System.err.println("Supposed to be bad: " + file.getName());
                    errorCount++;
                } else {
                    System.out.println(file.getName() + " -> " + result.hasFailures());
                }
            } catch (RuntimeException ex) {
                System.err.println("Exception while parsing " + file.getName() );
                exceptionCount++;
            }
        }

        System.out.println(objectCount + " objects: " + errorCount + " errors, " + exceptionCount + " exceptions");
    }
}
