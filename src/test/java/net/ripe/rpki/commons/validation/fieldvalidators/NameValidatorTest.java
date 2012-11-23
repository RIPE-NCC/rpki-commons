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
package net.ripe.rpki.commons.validation.fieldvalidators;

import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.util.Collections;
import java.util.List;

import net.ripe.rpki.commons.validation.ValidationCheck;

import org.junit.Test;


public class NameValidatorTest {

    private static final List<String> EXISTING_NAMES = Collections.singletonList("MyRoa");

    private NameValidator subject = new NameValidator(EXISTING_NAMES);


    @Test
    public void shouldPassWithCorrectName() {
        FieldValidationResult result = subject.validate("Sample ROA");
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckIfNameIsNull() {
        FieldValidationResult result = subject.validate(null);

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_REQUIRED);
    }

    @Test
    public void shouldCheckIfNameIsBlank() {
        FieldValidationResult result = subject.validate(" ");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_REQUIRED);
    }

    @Test
    public void shouldCheckNamePattern() {
        FieldValidationResult result = subject.validate("$%");

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_PATTERN);
    }

    @Test
    public void shouldCheckForDuplicates() {
        FieldValidationResult result = subject.validate(EXISTING_NAMES.get(0));

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_ALREADY_EXISTS);
    }

    @Test
    public void shouldSkipDuplicateCheckIfNameListNotSpecified() {
        subject = new NameValidator();
        FieldValidationResult result = subject.validate("My Roa");

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldCheckNameLength() {
        StringBuilder sb = new StringBuilder();
        for(int i=0; i<2000; i++) {
            sb.append('x');
        }
        FieldValidationResult result = subject.validate(sb.toString());

        assertTrue(result.hasFailures());

        List<ValidationCheck> failures = result.getFailures();
        assertEquals(1, failures.size());
        assertEquals(failures.iterator().next().getKey(), ROA_SPECIFICATION_NAME_LENGTH);
    }
}
