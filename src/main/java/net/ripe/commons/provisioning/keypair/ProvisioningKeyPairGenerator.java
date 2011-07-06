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
package net.ripe.commons.provisioning.keypair;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.RSAKeyGenParameterSpec;


/**
 * The provisioning draft refers to this section for the algorithm,
 * key size and public exponent:
 *
 * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
 */
public final class ProvisioningKeyPairGenerator {

    private static final String ALGORITHM = "RSA";
    private static final int IDENTITY_KEY_SIZE = 2048;
    public static final String DEFAULT_KEYPAIR_PROVIDER = "SunRsaSign";

    private ProvisioningKeyPairGenerator() {
        //Utility classes should not have a public or default constructor.
    }
    
    /**
     * Make a Provisioning Key Pair using the DEFAULT_KEYPAIR_PROVIDER
     */
    public static KeyPair generate() {
        return generate(DEFAULT_KEYPAIR_PROVIDER);
    }

    public static KeyPair generate(String provider) {
        try {
            KeyPairGenerator generator;
            generator = KeyPairGenerator.getInstance(ALGORITHM, provider);
            generator.initialize(new RSAKeyGenParameterSpec(IDENTITY_KEY_SIZE, RSAKeyGenParameterSpec.F4));
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new ProvisioningKeyPairGeneratorException(e);
        } catch (NoSuchProviderException e) {
            throw new ProvisioningKeyPairGeneratorException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new ProvisioningKeyPairGeneratorException(e);
        }
    }
}
