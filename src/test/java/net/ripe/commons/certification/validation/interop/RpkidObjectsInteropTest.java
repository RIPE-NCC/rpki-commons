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
package net.ripe.commons.certification.validation.interop;

import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsParser;
import net.ripe.commons.certification.validation.ValidationResult;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class RpkidObjectsInteropTest {

    private static final String PATH_TO_RPKID_OBJECTS = "src/test/resources/interop/rpkid-objects/";

    @Test
    public void shouldValidateRoa() throws IOException {
        byte[] encoded = FileUtils.readFileToByteArray(new File(PATH_TO_RPKID_OBJECTS + "nI2bsx18I5mlex8lBpY0WSJUYio.roa"));

        RoaCmsParser parser = new RoaCmsParser();
        parser.parse("roa", encoded);
        ValidationResult validationResult = parser.getValidationResult();
        
        assertFalse(validationResult.hasFailures());
        
        RoaCms roa = parser.getRoaCms();
        assertNotNull(roa.getContentType());
    }

//    @Test
//    public void shouldParseBinaryRoaBlob() {
//        byte[] encoded = {48, -126, 1, -79, 48, -127, -102, 2, 1, 1, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 48, 52, 49, 50, 48, 48, 6, 3, 85, 4, 3, 19, 41, 80, 115, 101, 117, 100, 111, 45, 65, 82, 73, 78, 32, 116, 101, 115, 116, 98, 101, 100, 32, 114, 111, 111, 116, 32, 82, 80, 75, 73, 32, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 23, 13, 49, 49, 49, 49, 49, 51, 49, 49, 48, 50, 51, 57, 90, 23, 13, 49, 49, 49, 50, 49, 51, 49, 49, 48, 50, 51, 57, 90, -96, 50, 48, 48, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, -128, 20, -72, 20, 93, 19, 83, 125, -82, 110, -30, -29, -107, -124, -88, -103, -21, 125, 26, 125, -27, -33, 48, 13, 6, 3, 85, 29, 20, 4, 6, 2, 4, 78, -65, -93, -49, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 11, 5, 0, 3, -126, 1, 1, 0, 8, -31, 77, -5, -43, -5, -25, 36, -101, 36, -84, -35, 99, 27, -23, 51, -113, 39, -35, 49, -7, -91, 29, 27, 83, 115, -52, -32, 90, -30, -90, -81, -13, 41, -79, -63, 82, -24, 91, 46, 48, -112, 74, 7, -81, 117, -30, 111, -29, -6, 47, 104, -4, 7, -57, -1, -92, 16, 88, 74, 94, 34, -33, 9, 106, 96, -21, 122, -119, -44, -101, -113, 51, 52, -108, 112, 81, -89, 39, 122, 121, -41, -75, 18, -15, 36, -99, -85, -74, -47, -57, -57, 127, 122, -32, -97, 115, 108, -8, 20, -54, 127, 56, -68, 126, 19, -94, 73, 116, -113, 51, 0, -1, -90, -86, -104, -62, -73, 100, 70, 111, 93, 102, -38, -60, 35, -83, -64, 75, -122, -5, -70, -93, -13, -104, -70, -105, -13, -127, 33, -16, -99, 55, 54, -76, 125, -126, 89, -66, 32, 59, -85, 104, 101, 49, 38, -16, 31, -2, -85, 31, 89, 110, 64, 9, 20, -112, 46, 52, 114, 46, -27, 117, -103, 44, -4, -71, 51, 6, -31, 110, -35, -18, 40, 60, 57, -79, 67, -99, -1, -43, -55, -70, 24, -5, 92, 115, 90, 105, -55, 95, -112, -99, 80, -12, 4, -59, -26, 37, -52, -110, -49, -107, 92, -122, 90, 106, 43, 91, 6, 109, 10, 19, 58, -27, 91, 31, -71, -86, 75, 92, -106, -109, 88, 99, 39, 30, 13, 79, -83, 72, 15, -61, 0, -61, 33, -36, 10, 52, -84, 81, 52, 122, -35, 120, -56};
//        RoaCmsParser parser = new RoaCmsParser();
//        parser.parse("roa", encoded);
//        ValidationResult validationResult = parser.getValidationResult();
//
//        assertFalse(validationResult.hasFailures());
//
//        RoaCms roa = parser.getRoaCms();
//        assertNotNull(roa.getContentType());
//    }

}
