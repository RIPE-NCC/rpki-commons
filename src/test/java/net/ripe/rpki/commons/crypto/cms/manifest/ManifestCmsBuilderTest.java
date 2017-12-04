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

import net.ripe.rpki.commons.FixedDateRule;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;

import static net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParserTest.*;
import static net.ripe.rpki.commons.crypto.util.Asn1UtilTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;


public class ManifestCmsBuilderTest {

    @Rule
    public FixedDateRule fixedDateRule = new FixedDateRule(THIS_UPDATE_TIME);

    private ManifestCmsBuilder subject = new ManifestCmsBuilder();


    @Before
    public void setUp() {
        subject.withManifestNumber(BigInteger.valueOf(68));
        subject.withThisUpdateTime(THIS_UPDATE_TIME);
        subject.withNextUpdateTime(NEXT_UPDATE_TIME);
        subject.withCertificate(createValidManifestEECertificate());
        subject.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
    }


    @Test
    public void shouldTrackFilenameAndHash() {
        byte[] content = {1, 2, 3, 4};
        subject.addFile("foo1", content);
        subject.addFile("foo3", content);

        ManifestCms result = subject.build(TEST_KEY_PAIR.getPrivate());
        assertEquals(2, result.size());
        assertTrue(result.containsFile("foo1"));
        assertTrue(result.containsFile("foo3"));
        assertFalse(result.containsFile("abracadabra"));
    }

    @SuppressWarnings("deprecation")
    @Test
    public void shouldCalculateHashAndWriteFile() throws IOException {
        byte[] contents = "contents".getBytes();
        subject.addFile("foo1", contents);

        ManifestCms result = subject.build(TEST_KEY_PAIR.getPrivate());
        assertEquals(1, result.size());
        assertTrue(result.containsFile("foo1"));

        // The hash below I got using 'shasum -a 256 /tmp/foo1' on OSX, where /tmp/foo1 is the file written above...
        byte[] expectedHash = Hex.decode("d1b2a59fbea7e20077af9f91b27e95e865061b270be03ff539ab3b73587882e8");
        assertArrayEquals(expectedHash, result.getHash("foo1"));

        assertTrue(result.verifyFileContents("foo1", contents));
        assertFalse(result.verifyFileContents("foo1", Hex.decode("deadbeaf")));
    }

    @Test
    public void shouldEncodeFileAndHash() {
        assertEncoded(ENCODED_FILE_AND_HASH_1, subject.encodeFileAndHash("foo1", FOO_HASH));
    }

    @Test
    public void shouldEncodeEmptyFileList() {
        assertEncoded(ENCODED_EMPTY_FILE_LIST, subject.encodeFileList());
    }

    @Test
    public void shouldEncodeFileList() {
        subject.addFile("foo1", FOO_CONTENT);
        subject.addFile("BaR", BAR_CONTENT);
        assertEncoded(ENCODED_FILE_LIST, subject.encodeFileList());
    }

    @Test
    public void shouldEncodeManifest() {
        subject.addFile("foo1", FOO_CONTENT);
        subject.addFile("BaR", BAR_CONTENT);
        assertArrayEquals(ENCODED_MANIFEST, subject.encodeManifest());
    }
}
