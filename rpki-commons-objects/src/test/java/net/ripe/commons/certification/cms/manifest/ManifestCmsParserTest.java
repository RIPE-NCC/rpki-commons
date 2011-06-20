package net.ripe.commons.certification.cms.manifest;

import static net.ripe.commons.certification.Asn1Util.*;
import static net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper.*;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Map;
import java.util.TreeMap;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.DERTags;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.DateTimeZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class ManifestCmsParserTest {

	public static final X500Principal TEST_DN = new X500Principal("CN=Test");
    public static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;

    public static final DateTime THIS_UPDATE_TIME = new DateTime(2008, 9, 1, 22, 43, 29, 0, DateTimeZone.UTC);
    public static final DateTime NEXT_UPDATE_TIME = new DateTime(2008, 9, 2, 6, 43, 29, 0, DateTimeZone.UTC);

    public static final byte[] HASH_1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    public static final byte[] HASH_2 = { 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

	public static final byte[] ENCODED_FILE_AND_HASH_1 = {
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, 0x29,
		DERTags.IA5_STRING, 0x04, (byte) 'f', (byte) 'o', (byte) 'o', (byte) '1',
		DERTags.BIT_STRING, 0x21, 0x00,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
	};

	public static final byte[] ENCODED_EMPTY_FILE_LIST = {
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, 0x0,
	};

	public static final byte[] ENCODED_FILE_LIST = {
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, 0x55,
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, 0x28,
		DERTags.IA5_STRING, 0x03, (byte) 'B', (byte) 'a', (byte) 'R',
		DERTags.BIT_STRING, 0x21, 0x00,
		32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, 0x29,
		DERTags.IA5_STRING, 0x04, (byte) 'f', (byte) 'o', (byte) 'o', (byte) '1',
		DERTags.BIT_STRING, 0x21, 0x00,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	};

	public static final byte[] ENCODED_MANIFEST = {
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, (byte) 0x81, (byte) 0x87,
		DERTags.INTEGER, 0x01, 0x44, // manifest number
		DERTags.GENERALIZED_TIME, 0x0F,
		(byte) '2', (byte) '0', (byte) '0', (byte) '8', (byte) '0', (byte) '9', (byte) '0', (byte) '1', (byte) '2', (byte) '2', (byte) '4', (byte) '3', (byte) '2', (byte) '9', (byte) 'Z',
		DERTags.GENERALIZED_TIME, 0x0F,
		(byte) '2', (byte) '0', (byte) '0', (byte) '8', (byte) '0', (byte) '9', (byte) '0', (byte) '2', (byte) '0', (byte) '6', (byte) '4', (byte) '3', (byte) '2', (byte) '9', (byte) 'Z',
		DERTags.OBJECT_IDENTIFIER, 0x09, // SHA-256 OID
		96, -122, 72, 1, 101, 3, 4, 2, 1,
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, 0x55,
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, 0x28,
		DERTags.IA5_STRING, 0x03, (byte) 'B', (byte) 'a', (byte) 'R',
		DERTags.BIT_STRING, 0x21, 0x00,
		32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
		DERTags.SEQUENCE | DERTags.CONSTRUCTED, 0x29,
		DERTags.IA5_STRING, 0x04, (byte) 'f', (byte) 'o', (byte) 'o', (byte) '1',
		DERTags.BIT_STRING, 0x21, 0x00,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	};

	private ManifestCmsParser parser;


	static X509ResourceCertificate createValidManifestEECertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withSubjectDN(TEST_DN).withIssuerDN(TEST_DN).withSerial(BigInteger.ONE);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withResources(InheritedIpResourceSet.getInstance());
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
        parser = new ManifestCmsParser();

        DateTimeUtils.setCurrentMillisFixed(THIS_UPDATE_TIME.getMillis());
        ManifestCmsBuilder builder = new ManifestCmsBuilder();
        builder.withCertificate(createValidManifestEECertificate()).withManifestNumber(BigInteger.valueOf(68));
        builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
        builder.putFile("foo1", HASH_1);
        builder.putFile("BaR", HASH_2);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        parser.parse("test", builder.build(TEST_KEY_PAIR.getPrivate()).getEncoded());
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
    	assertArrayEquals(HASH_1, actual.get("foo1"));
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
    	assertArrayEquals(HASH_1, actual.get("foo1"));
    	assertTrue(actual.containsKey("BaR"));
    	assertArrayEquals(HASH_2, actual.get("BaR"));
    }

    @Test
    public void shouldDecodeManifest() {
    	parser.decodeManifest(decode(ENCODED_MANIFEST));
    	ManifestCms manifest = parser.getManifestCms();
    	assertEquals(0, manifest.getVersion());
    	assertEquals(BigInteger.valueOf(68), manifest.getNumber());
    	assertEquals(THIS_UPDATE_TIME, manifest.getThisUpdateTime());
    	assertEquals(NEXT_UPDATE_TIME, manifest.getNextUpdateTime());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldRejectManifestWithNonInheritEECert() {
        DateTimeUtils.setCurrentMillisFixed(THIS_UPDATE_TIME.getMillis());
        ManifestCmsBuilder builder = new ManifestCmsBuilder();

        // Use 10/8 EE cert
        builder.withCertificate(createTenSlashEightResourceCertificate()).withManifestNumber(BigInteger.valueOf(68));
        builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
        builder.putFile("foo1", HASH_1);
        builder.putFile("BaR", HASH_2);

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
