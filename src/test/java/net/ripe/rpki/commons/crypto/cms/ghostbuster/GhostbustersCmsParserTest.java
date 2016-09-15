/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
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
package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertEquals;

public class GhostbustersCmsParserTest {
    @Test
    public void testShouldParseGoodGbr() throws Exception {
        String path = "src/test/resources/conformance/root/goodRealGbrNothingIsWrong.gbr";
        byte[] bytes = FileUtils.readFileToByteArray(new File(path));
        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        parser.parse(ValidationResult.withLocation("test1.gbr"), bytes);
        String vCard = parser.getGhostbustersCms().getvCard();
        assertEquals("BEGIN:VCARD\r\n" +
                "VERSION:3.0\r\n" +
                "ADR:;;5147 Crystal Springs Drive NE;Bainbridge Island;Washington;98110;Uni\r\n" +
                " ted States\r\n" +
                "EMAIL:randy@psg.com\r\n" +
                "FN:Randy Bush\r\n" +
                "N:;;;;\r\n" +
                "ORG:RGnet\\, LLC\r\n" +
                "TEL:+1 206 356 8341\r\n" +
                "END:VCARD\r\n", vCard);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testShouldParseBadGbr() throws Exception {
        String path = "src/test/resources/conformance/root/badGBRNotVCard.gbr";
        byte[] bytes = FileUtils.readFileToByteArray(new File(path));
        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        parser.parse(ValidationResult.withLocation("test2.gbr"), bytes);
        parser.getGhostbustersCms().getvCard();
    }
}