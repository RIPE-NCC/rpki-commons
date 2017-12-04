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

import com.google.common.io.ByteStreams;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


public final class KeyStoreUtil {

    private static final char[] KEYSTORE_PASSPHRASE = "4AD8A8BD-A001-4400-8DAC-5F3B97F07DE5".toCharArray();

    static final String KEYSTORE_KEY_ALIAS = "mykey1";


    private KeyStoreUtil() {
        //Utility classes should not have a public or default constructor.
    }

    public static KeyStore createKeyStoreForKeyPair(KeyPair keyPair, String keyStoreProvider, String signatureProvider, String keyStoreType) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
            keyStore.load(null, KEYSTORE_PASSPHRASE);
            keyStore.aliases();
            X509Certificate certificate = generateCertificate(keyPair, signatureProvider);
            keyStore.setKeyEntry(KEYSTORE_KEY_ALIAS, keyPair.getPrivate(), KEYSTORE_PASSPHRASE, new Certificate[]{certificate});
            return keyStore;
        } catch (GeneralSecurityException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        } catch (IOException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        }
    }

    public static KeyPair getKeyPairFromKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
        KeyStore keyStore = loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType);
        return getKeyPairFromKeyStore(keyStore);
    }

    public static byte[] storeKeyStore(KeyStore keyStore) {
        ByteArrayOutputStream keyStoreOS = new ByteArrayOutputStream();
        try {
            keyStore.store(keyStoreOS, KEYSTORE_PASSPHRASE);
            keyStoreOS.flush();
            return keyStoreOS.toByteArray();
        } catch (GeneralSecurityException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        } catch (IOException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        }
    }

    public static KeyStore clearKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
        KeyStore keyStore = loadKeyStore(keyStoreData, keyStoreProvider, keyStoreType);
        clearKeyStore(keyStore);
        return keyStore;
    }

    private static KeyStore clearKeyStore(KeyStore keyStore) {
        try {
            if (keyStore.containsAlias(KEYSTORE_KEY_ALIAS)) {
                keyStore.deleteEntry(KEYSTORE_KEY_ALIAS);
                keyStore.store(ByteStreams.nullOutputStream(), KEYSTORE_PASSPHRASE);
            }
            return keyStore;
        } catch (GeneralSecurityException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        } catch (IOException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        }
    }

    private static KeyPair getKeyPairFromKeyStore(KeyStore keyStore) {
        try {
            Certificate certificate = keyStore.getCertificateChain(KEYSTORE_KEY_ALIAS)[0];
            PublicKey publicKey = certificate.getPublicKey();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYSTORE_KEY_ALIAS, KEYSTORE_PASSPHRASE);
            return new KeyPair(publicKey, privateKey);
        } catch (GeneralSecurityException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        }
    }

    private static KeyStore loadKeyStore(byte[] keyStoreData, String keyStoreProvider, String keyStoreType) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
            keyStore.load(new ByteArrayInputStream(keyStoreData), KEYSTORE_PASSPHRASE);
            return keyStore;
        } catch (GeneralSecurityException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        } catch (IOException e) {
            throw new net.ripe.rpki.commons.crypto.util.KeyStoreException(e);
        }
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String signatureProvider) {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal("CN=issuer"),
                BigInteger.ONE,
                new DateTime().minusYears(2).toDate(),
                new DateTime().minusYears(1).toDate(),
                new X500Principal("CN=subject"),
                keyPair.getPublic());
        try {
            ContentSigner sigGen = new JcaContentSignerBuilder(X509CertificateBuilderHelper.DEFAULT_SIGNATURE_ALGORITHM).setProvider(signatureProvider).build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(builder.build(sigGen));
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
