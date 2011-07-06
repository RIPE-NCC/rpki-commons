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
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.StringUtils;

public class PrefixValidator implements FieldValidator {

    private static final long serialVersionUID = 5663911278468240006L;

    private final IpResourceSet caResources;


    public PrefixValidator(IpResourceSet caResources) {
        this.caResources = caResources;
    }

    @Override
    public ValidationResult validate(String prefix) {
        ValidationResult result = new ValidationResult();
        if (!result.isFalse(StringUtils.isBlank(prefix), ROA_SPECIFICATION_PREFIX_REQUIRED)) {
            return result;
        }

        IpRange parsedPrefix = null;
        boolean validPrefix = true;
        try {
            parsedPrefix = IpRange.parse(prefix);
        } catch (IllegalArgumentException e) {
            validPrefix = false;
        }
        result.isTrue(validPrefix, ROA_SPECIFICATION_PREFIX_VALID, prefix);

        if (validPrefix) {
            result.isTrue(parsedPrefix.isLegalPrefix(), ROA_SPECIFICATION_PREFIX_VALID, prefix);
            result.isTrue(isResourceHeldByTheCurrentCA(parsedPrefix), ROA_SPECIFICATION_PREFIX_NOT_HELD_BY_CA, prefix);
        }

        return result;
    }

    private boolean isResourceHeldByTheCurrentCA(IpRange prefix) {
        IpResourceSet resourceSet = new IpResourceSet(prefix);
        resourceSet.removeAll(caResources);
        return resourceSet.isEmpty();
    }
}
