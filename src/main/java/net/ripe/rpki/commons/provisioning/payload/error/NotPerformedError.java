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
package net.ripe.rpki.commons.provisioning.payload.error;

import java.util.HashMap;
import java.util.Map;

public enum NotPerformedError {

    ALREADY_PROCESSING_REQUEST(1101),
    VERSION_NUMBER_ERROR(1102),
    UNRECOGNIZED_REQUEST_TYPE(1103),
    REQUEST_SCHEDULED_FOR_PROCESSING(1104),
    REQ_NO_SUCH_RESOURCE_CLASS(1201),
    REQ_NO_RESOURCES_ALLOTED_IN_RESOURCE_CLASS(1202),
    REQ_BADLY_FORMED_CERTIFICATE_REQUEST(1203),
    REQ_ALREADY_USED_KEY_IN_REQUEST(1204),
    REV_NO_SUCH_RESOURCE_CLASS(1301),
    REV_NO_SUCH_KEY(1302),
    INTERNAL_SERVER_ERROR(2001);

    private Integer errorCode;

    private static final Map<Integer, NotPerformedError> CODE_MAP;

    static {
        CODE_MAP = new HashMap<Integer, NotPerformedError>();

        for (NotPerformedError error : NotPerformedError.values()) {
            CODE_MAP.put(error.getErrorCode(), error);
        }
    }

    NotPerformedError(Integer errorCode) {
        this.errorCode = errorCode;
    }

    public Integer getErrorCode() {
        return errorCode;
    }

    public static NotPerformedError getError(Integer errorCode) {
        return CODE_MAP.get(errorCode);
    }
}
