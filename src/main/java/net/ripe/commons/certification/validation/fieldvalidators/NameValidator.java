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
package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

public class NameValidator implements FieldValidator {

    private static final String NAME_PATTERN_STRING = "[A-Za-z0-9-_:@.+ <>]+";
    private static final Pattern NAME_PATTERN = Pattern.compile(NAME_PATTERN_STRING);
    private static final int MAX_NAME_LENGTH = 2000;
    private static final long serialVersionUID = -938017808691917812L;
    private final List<String> existingNames;


    public NameValidator() {
        this.existingNames = Collections.<String>emptyList();
    }

    public NameValidator(List<String> existingNames) {
        Validate.notNull(existingNames);
        this.existingNames = existingNames;
    }

    @Override
    public FieldValidationResult validate(String name) {
        FieldValidationResult result = new FieldValidationResult();
        if (!result.isFalse(StringUtils.isBlank(name), ROA_SPECIFICATION_NAME_REQUIRED)) {
            return result;
        }
        result.isTrue(NAME_PATTERN.matcher(name).matches(), ROA_SPECIFICATION_NAME_PATTERN);
        result.isTrue(name.length() < MAX_NAME_LENGTH, ROA_SPECIFICATION_NAME_LENGTH, Integer.valueOf(MAX_NAME_LENGTH).toString());
        result.isFalse(existingNames.contains(name), ROA_SPECIFICATION_NAME_ALREADY_EXISTS);
        return result;
    }
}
