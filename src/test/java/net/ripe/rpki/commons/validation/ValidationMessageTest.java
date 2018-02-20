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
package net.ripe.rpki.commons.validation;

import org.junit.Test;

import java.util.Locale;

import static org.junit.Assert.*;


public class ValidationMessageTest {

    @Test
    public void shouldResolveMessage() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck));
    }

    @Test
    public void shouldFormatMessageArguments() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.VALIDATOR_URI_HOST, "rsync://localhost/path/");
        assertEquals("URI 'rsync://localhost/path/' contains a host", ValidationMessage.getMessage(validationCheck));
    }

    @Test
    public void shouldUseSpecifiedLocale() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Het certificaat kon ingelezen worden", ValidationMessage.getMessage(validationCheck, Locale.forLanguageTag("test")));
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck, Locale.US));
    }

    @Test
    public void shouldFallbackToDefaultLocale() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck, Locale.FRENCH));
    }

    @Test
    public void shouldFallbackToLanguageFromFullLocale() {
        ValidationCheck validationCheck = new ValidationCheck(ValidationStatus.PASSED, ValidationString.CERTIFICATE_PARSED);
        assertEquals("Certificate can be parsed", ValidationMessage.getMessage(validationCheck, Locale.US));
    }
}
