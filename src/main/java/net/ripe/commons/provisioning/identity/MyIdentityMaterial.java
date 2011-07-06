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
package net.ripe.commons.provisioning.identity;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificate;

import java.io.Serializable;
import java.security.KeyPair;

/**
 * Wrapper class for the identity information relevant to <b>MY SELF</b> in the provisioning protocol
 */
public class MyIdentityMaterial implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private KeyPair identityKeyPair;
    private X509Crl identityCrl;
    private ProvisioningIdentityCertificate identityCertificate;

    public MyIdentityMaterial(KeyPair identityKeyPair, X509Crl identityCrl, ProvisioningIdentityCertificate identityCertificate) {
        this.identityKeyPair = identityKeyPair;
        this.identityCrl = identityCrl;
        this.identityCertificate = identityCertificate;
    }

    public KeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    public X509Crl getIdentityCrl() {
        return identityCrl;
    }

    public ProvisioningIdentityCertificate getIdentityCertificate() {
        return identityCertificate;
    }
}
