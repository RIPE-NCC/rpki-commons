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
package net.ripe.rpki.commons.provisioning.protocol;

public enum ResponseExceptionType {
    BAD_DATA(400 /*HttpServletResponse.SC_BAD_REQUEST*/, "Could not validate client's request"),
    UNKNOWN_PROVISIONING_URL(400, "Provisioning URL not recognized"),
    UNKNOWN_SENDER(400, "sender not recognized"),
    UNKNOWN_RECIPIENT(400, "recipient not recognized"),
    BAD_SENDER_AND_RECIPIENT(400, "sender and recipient do not match"),
    POTENTIAL_REPLAY_ATTACK(400, "potential replay attack (request signed before last seen signing time)"),

    THROTTLING(503 /*HttpServletResponse.SC_SERVICE_UNAVAILABLE*/, "The server cannot handle your request at this time");

    private int httpResponseCode;
    private String description;

    private ResponseExceptionType(int httpResponseCode, String description) {
        this.httpResponseCode = httpResponseCode;
        this.description = description;
    }

    public int getHttpResponseCode() {
        return httpResponseCode;
    }

    public String getDescription() {
        return description;
    }
}
