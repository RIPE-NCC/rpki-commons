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
package net.ripe.rpki.commons.crypto.util;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyPairFactory {

    public static final String ALGORITHM = "RSA";

    public static final int RPKI_KEY_PAIR_SIZE = 2048;

    /**
     * F4 Public Exponent
     */
    public static final BigInteger PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;

    private final String provider;

    public KeyPairFactory(String provider) {
        this.provider = provider;
    }

    public KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, provider);
            generator.initialize(new RSAKeyGenParameterSpec(RPKI_KEY_PAIR_SIZE, PUBLIC_EXPONENT));
            return generator.generateKeyPair();
        } catch (NoSuchProviderException e) {
            throw new KeyPairFactoryException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    /**
     * Decodes an X.509 encoded public key.
     *
     * @param encoded the encoded public key.
     * @return the PublicKey.
     */
    public static PublicKey decodePublicKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException e) {
            throw new KeyPairFactoryException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    /**
     * Decodes a PKCS#8 encoded private key. This is the default encoding for
     * the private key getEncoded method.
     *
     * @param encoded the encoded data.
     * @return the PrivateKey.
     */
    public static PrivateKey decodePrivateKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException e) {
            throw new KeyPairFactoryException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyPairFactoryException(e);
        }
    }

    public KeyPairFactory withProvider(String provider) {
        return new KeyPairFactory(provider);
    }
}
