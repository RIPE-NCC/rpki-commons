/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.util.encoders.Hex;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public final class KeyPairUtil {

    private KeyPairUtil() {
        // Utility classes should not have a public or default constructor.
    }

    /**
     * Get Base64 encoded public key as string. Primarily for generating
     * filenames and transferring public keys across the wire. Strips the trailing
     * '=' characters, which some decoders may not like!
     */
    public static String getEncodedKeyIdentifier(PublicKey key) {
        String encoded = base64UrlEncode(getKeyIdentifier(key));
        return StringUtils.stripEnd(encoded, "="); // No need to decode, so we can strip padding.
    }

    /**
     * Get ASCII Hex encoded hash of the public key; for use in certificate
     * subjects as described here:
     * http://tools.ietf.org/html/draft-ietf-sidr-res-certs-21#section-8
     */
    public static String getAsciiHexEncodedPublicKeyHash(PublicKey publicKey) {
        return hexEncodeHashData(getKeyIdentifier(publicKey));
    }

    static String hexEncodeHashData(byte[] keyHashData) {
        return Hex.toHexString(keyHashData);
    }

    public static byte[] getKeyIdentifier(PublicKey key) {
        try {
            return new JcaX509ExtensionUtils().createSubjectKeyIdentifier(key).getKeyIdentifier();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Could not get SubjectKeyIdentifierStructure from key", e);
        }
    }

    public static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data);
    }

}
