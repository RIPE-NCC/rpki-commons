/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
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
package net.ripe.rpki.commons.provisioning.identity;

import lombok.EqualsAndHashCode;
import lombok.ToString;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;

import java.net.URI;

@EqualsAndHashCode(doNotUseGetters = true)
@ToString(doNotUseGetters = true)
public final class ParentIdentity {

    public static final int VERSION = 1;
    private final String childHandle;
    private final String parentHandle;
    private final URI upDownUrl;
    private final ProvisioningIdentityCertificate parentIdCertificate;


    public ParentIdentity(URI upDownUrl, String parentHandle,
                          String childHandle,
                          ProvisioningIdentityCertificate parentIdCertificate) {
        this.upDownUrl = upDownUrl;
        this.parentHandle = parentHandle;
        this.childHandle = childHandle;
        this.parentIdCertificate = parentIdCertificate;
    }

    public String getChildHandle() {
        return childHandle;
    }

    public String getParentHandle() {
        return parentHandle;
    }

    public ProvisioningIdentityCertificate getParentIdCertificate() {
        return parentIdCertificate;
    }

    public URI getUpDownUrl() {
        return upDownUrl;
    }

    public int getVersion() {
        return VERSION;
    }
}
