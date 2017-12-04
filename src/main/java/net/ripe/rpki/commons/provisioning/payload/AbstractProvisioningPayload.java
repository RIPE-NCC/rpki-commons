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
package net.ripe.rpki.commons.provisioning.payload;

import com.thoughtworks.xstream.annotations.XStreamAsAttribute;

public abstract class AbstractProvisioningPayload {

    public static final String DEFAULT_SENDER = "sender";
    public static final String DEFAULT_RECIPIENT = "recipient";

    public static final Integer SUPPORTED_VERSION = 1;

    @XStreamAsAttribute
    private Integer version;

    @XStreamAsAttribute
    private String sender = DEFAULT_SENDER;

    @XStreamAsAttribute
    private String recipient = DEFAULT_RECIPIENT;

    @XStreamAsAttribute
    private PayloadMessageType type;

    protected AbstractProvisioningPayload(PayloadMessageType type) {
        this(SUPPORTED_VERSION, type);
    }

    private AbstractProvisioningPayload(Integer version, PayloadMessageType type) {
        this.version = version;
        this.type = type;
    }

    /**
     * Note: This field is used by some implementations to work out who the players
     * are in an exchange of ProvisioningCmsObjects. (eg APNIC). This setter is
     * provided to make it easier to set this value 'close' to your code that deals
     * with this actual exchange, as opposed to the code that deals with the other
     * 'content' of the payload.
     */
    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    /**
     * Note: This field is used by some implementations to work out who the players
     * are in an exchange of ProvisioningCmsObjects. (eg APNIC). This setter is
     * provided to make it easier to set this value 'close' to your code that deals
     * with this actual exchange, as opposed to the code that deals with the other
     * 'content' of the payload.
     */
    public void setSender(String sender) {
        this.sender = sender;
    }

    public Integer getVersion() {
        return version;
    }

    public String getSender() {
        return sender;
    }

    public String getRecipient() {
        return recipient;
    }

    public PayloadMessageType getType() {
        return type;
    }

}
