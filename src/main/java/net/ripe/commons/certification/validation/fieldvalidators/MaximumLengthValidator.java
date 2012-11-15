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
package net.ripe.commons.certification.validation.fieldvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;
import net.ripe.ipresource.IpRange;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

public class MaximumLengthValidator implements FieldValidator {

    private static final long serialVersionUID = 2691080076021637679L;

    private final IpRange prefix;


    public MaximumLengthValidator(IpRange prefix) {
        Validate.notNull(prefix);
        this.prefix = prefix;
    }

    @Override
    public FieldValidationResult validate(String maxLength) {
        FieldValidationResult result = new FieldValidationResult();

        if (StringUtils.isBlank(maxLength)) {
            return result;
        }

        Integer maximumLength = null;
        boolean isMaxLengthValid = true;
        try {
            maximumLength = Integer.parseInt(maxLength);
        } catch (NumberFormatException e) {
            isMaxLengthValid = false;
        }
        result.isTrue(isMaxLengthValid, ROA_SPECIFICATION_MAX_LENGTH_VALID);

        if (isMaxLengthValid) {
            result.isTrue(isMaximumLengthValid(maximumLength), ROA_SPECIFICATION_MAX_LENGTH_VALID);
        }

        return result;
    }

    private boolean isMaximumLengthValid(Integer maximumLength) {
        return maximumLength == null || (maximumLength >= getMinimumValidLength() && maximumLength <= getMaximumValidLength());
    }

    private int getMaximumValidLength() {
        return prefix.getType().getBitSize() - 2;
    }

    private int getMinimumValidLength() {
        return prefix.getPrefixLength();
    }
}
