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
package net.ripe.rpki.commons.crypto.cms.manifest;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import org.bouncycastle.asn1.BERTags;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.DateTimeZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.EnumSet;
import java.util.Map;
import java.util.TreeMap;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;


public class ManifestCmsParserTest {

    public static final X500Principal TEST_DN = new X500Principal("CN=Test");
    public static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;

    public static final DateTime THIS_UPDATE_TIME = new DateTime(2008, 9, 1, 22, 43, 29, 0, DateTimeZone.UTC);
    public static final DateTime NEXT_UPDATE_TIME = new DateTime(2008, 9, 2, 6, 43, 29, 0, DateTimeZone.UTC);

    public static final byte[] FOO_CONTENT = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

    public static final byte[] FOO_HASH = {-82, 33, 108, 46, -11, 36, 122, 55, -126, -63, 53, -17, -94, 121, -93, -28, -51, -58, 16, -108, 39, 15,
            93, 43, -27, -116, 98, 4, -73, -90, 18, -55};

    public static final byte[] BAR_CONTENT = {32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

    public static final byte[] BAR_HASH = {77, -99, -39, 69, 30, -61, 10, -3, -84, 18, 112, 23, -70, -73, 109, 38, -41, 79, 6, -17, -49, -88, -14,
            119, 85, -72, -77, 26, -93, -65, -28, -88};

    public static final byte[] ENCODED_FILE_AND_HASH_1 = {
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, 0x29,
            BERTags.IA5_STRING, 0x04, (byte) 'f', (byte) 'o', (byte) 'o', (byte) '1',
            BERTags.BIT_STRING, 0x21, 0x00,
            -82, 33, 108, 46, -11, 36, 122, 55, -126, -63, 53, -17, -94, 121,
            -93, -28, -51, -58, 16, -108, 39, 15, 93, 43, -27, -116, 98, 4, -73, -90, 18, -55
    };

    public static final byte[] ENCODED_EMPTY_FILE_LIST = {
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, 0x0,
    };

    public static final byte[] ENCODED_FILE_LIST = {
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, 0x55,
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, 0x28,
            BERTags.IA5_STRING, 0x03, (byte) 'B', (byte) 'a', (byte) 'R',
            BERTags.BIT_STRING, 0x21, 0x00,
            77, -99, -39, 69, 30, -61, 10, -3, -84, 18,
            112, 23, -70, -73, 109, 38, -41, 79, 6, -17, -49, -88, -14, 119, 85, -72, -77, 26, -93, -65, -28, -88,
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, 0x29,
            BERTags.IA5_STRING, 0x04, (byte) 'f', (byte) 'o', (byte) 'o', (byte) '1',
            BERTags.BIT_STRING, 0x21, 0x00,
            -82, 33, 108, 46, -11, 36, 122, 55, -126, -63, 53, -17, -94, 121, -93, -28, -51, -58, 16, -108, 39, 15,
            93, 43, -27, -116, 98, 4, -73, -90, 18, -55
    };

    public static final byte[] ENCODED_MANIFEST = {
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, (byte) 0x81, (byte) 0x87,
            BERTags.INTEGER, 0x01, 0x44, // manifest number
            BERTags.GENERALIZED_TIME, 0x0F,
            (byte) '2', (byte) '0', (byte) '0', (byte) '8', (byte) '0', (byte) '9', (byte) '0', (byte) '1', (byte) '2', (byte) '2', (byte) '4', (byte) '3', (byte) '2', (byte) '9', (byte) 'Z',
            BERTags.GENERALIZED_TIME, 0x0F,
            (byte) '2', (byte) '0', (byte) '0', (byte) '8', (byte) '0', (byte) '9', (byte) '0', (byte) '2', (byte) '0', (byte) '6', (byte) '4', (byte) '3', (byte) '2', (byte) '9', (byte) 'Z',
            BERTags.OBJECT_IDENTIFIER, 0x09, // SHA-256 OID
            96, -122, 72, 1, 101, 3, 4, 2, 1,
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, 0x55,
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, 0x28,
            BERTags.IA5_STRING, 0x03, (byte) 'B', (byte) 'a', (byte) 'R',
            BERTags.BIT_STRING, 0x21, 0x00,
            77, -99, -39, 69, 30, -61, 10, -3, -84, 18,
            112, 23, -70, -73, 109, 38, -41, 79, 6, -17, -49, -88, -14, 119, 85, -72, -77, 26, -93, -65, -28, -88,
            BERTags.SEQUENCE | BERTags.CONSTRUCTED, 0x29,
            BERTags.IA5_STRING, 0x04, (byte) 'f', (byte) 'o', (byte) 'o', (byte) '1',
            BERTags.BIT_STRING, 0x21, 0x00,
            -82, 33, 108, 46, -11, 36, 122, 55, -126, -63, 53, -17, -94, 121, -93, -28, -51, -58, 16, -108, 39, 15,
            93, 43, -27, -116, 98, 4, -73, -90, 18, -55,
    };

    private ManifestCmsParser parser;


    static X509ResourceCertificate createValidManifestEECertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withSubjectDN(TEST_DN).withIssuerDN(TEST_DN).withSerial(BigInteger.ONE);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withResources(new IpResourceSet());
        builder.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));
        builder.withValidityPeriod(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME));
        return builder.build();
    }

    static X509ResourceCertificate createTenSlashEightResourceCertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withSubjectDN(TEST_DN).withIssuerDN(TEST_DN).withSerial(BigInteger.ONE);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withResources(IpResourceSet.parse("10.0.0.0/8"));
        builder.withValidityPeriod(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME));
        return builder.build();
    }

    @Before
    public void setUp() {
        String location = "unknown.mft";
        parser = new ManifestCmsParser();

        DateTimeUtils.setCurrentMillisFixed(THIS_UPDATE_TIME.getMillis());
        ManifestCmsBuilder builder = new ManifestCmsBuilder();
        builder.withCertificate(createValidManifestEECertificate()).withManifestNumber(BigInteger.valueOf(68));
        builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
        builder.addFile("foo1", FOO_CONTENT);
        builder.addFile("BaR", BAR_CONTENT);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        parser.parse(location, builder.build(TEST_KEY_PAIR.getPrivate()).getEncoded());
    }

    @After
    public void tearDown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    public void shouldDecodeFileAndHash() {
        Map<String, byte[]> actual = new TreeMap<String, byte[]>();
        parser.decodeFileAndHash(actual, decode(ENCODED_FILE_AND_HASH_1));
        assertEquals(1, actual.size());
        assertTrue(actual.containsKey("foo1"));
        assertArrayEquals(FOO_HASH, actual.get("foo1"));
    }

    @Test
    public void shouldDecodeEmptyFileList() {
        Map<String, byte[]> actual = new TreeMap<String, byte[]>();
        parser.decodeFileList(actual, decode(ENCODED_EMPTY_FILE_LIST));
        assertTrue(actual.isEmpty());
    }

    @Test
    public void shouldDecodeFileList() {
        Map<String, byte[]> actual = new TreeMap<String, byte[]>();
        parser.decodeFileList(actual, decode(ENCODED_FILE_LIST));
        assertEquals(2, actual.size());
        assertTrue(actual.containsKey("foo1"));
        assertArrayEquals(FOO_HASH, actual.get("foo1"));
        assertTrue(actual.containsKey("BaR"));
        assertArrayEquals(BAR_HASH, actual.get("BaR"));
    }

    @Test
    public void shouldDecodeManifest() {
        parser.decodeAsn1Content(decode(ENCODED_MANIFEST));
        ManifestCms manifest = parser.getManifestCms();
        assertEquals(0, manifest.getVersion());
        assertEquals(BigInteger.valueOf(68), manifest.getNumber());
        assertEquals(THIS_UPDATE_TIME, manifest.getThisUpdateTime());
        assertEquals(NEXT_UPDATE_TIME, manifest.getNextUpdateTime());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldRejectManifestWithNonInheritEECert() {
        DateTimeUtils.setCurrentMillisFixed(THIS_UPDATE_TIME.getMillis());
        ManifestCmsBuilder builder = new ManifestCmsBuilder();

        // Use 10/8 EE cert
        builder.withCertificate(createTenSlashEightResourceCertificate()).withManifestNumber(BigInteger.valueOf(68));
        builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
        builder.addFile("foo1", FOO_CONTENT);
        builder.addFile("BaR", BAR_CONTENT);

        /* Now when we try to *build* we will be rejected.
         *
         * Tested this way because we have no other way to create an invalid manifest. The actual
         * code enforcing this check *is* in the parser class though. So this will also work for
         * Manifests set up by others. Our manifest builder uses this parser under the hood to this
         * validation just after creation of a new object, and before returning it, when we ask it to build..
         */
        builder.build(TEST_KEY_PAIR.getPrivate());
    }
}
