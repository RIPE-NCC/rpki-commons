package net.ripe.commons.certification.cms.manifest;

import static net.ripe.commons.certification.Asn1UtilTest.*;
import static net.ripe.commons.certification.cms.manifest.ManifestCmsParserTest.*;
import static net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;

import net.ripe.commons.certification.FixedDateRule;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;


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
        byte[] hash = { 1, 2, 3, 4 };
        subject.putFile("foo1", hash);
        subject.putFile("foo3", hash);

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
        assertEncoded(ENCODED_FILE_AND_HASH_1, subject.encodeFileAndHash("foo1", HASH_1));
    }

    @Test
    public void shouldEncodeEmptyFileList() {
        assertEncoded(ENCODED_EMPTY_FILE_LIST, subject.encodeFileList());
    }

    @Test
    public void shouldEncodeFileList() {
        subject.putFile("foo1", HASH_1);
        subject.putFile("BaR", HASH_2);
        assertEncoded(ENCODED_FILE_LIST, subject.encodeFileList());
    }

    @Test
    public void shouldEncodeManifest() {
        subject.putFile("foo1", HASH_1);
        subject.putFile("BaR", HASH_2);
        assertEncoded(ENCODED_MANIFEST, subject.encodeManifest());
    }
}
