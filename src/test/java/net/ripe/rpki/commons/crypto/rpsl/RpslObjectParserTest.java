package net.ripe.rpki.commons.crypto.rpsl;

import com.google.common.io.Files;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RpslObjectParserTest {

    private static final String PATH_TO_OBJECTS = "src/test/resources/apnic-rpsl-sig";
    public static final String TEST_CER = "test.cer";
    private RpslSigningCertificate signingCertificate;
    private PublicKey publicKey;
    private String testSignedObject;

    @Before
    private void loadTestCertificate() throws IOException {
        testSignedObject = Files.toString(new File(PATH_TO_OBJECTS, "rpsl-object.txt"), Charset.forName("UTF-8"));

        RpslSigningCertificateParser parser = new RpslSigningCertificateParser();
        byte[] encoded = Files.toByteArray(new File(PATH_TO_OBJECTS, TEST_CER));

        ValidationResult result = ValidationResult.withLocation(TEST_CER);
        parser.parse(result, encoded);
        assertFalse(result.hasFailures());

        signingCertificate = parser.getRpslSigningCertificate();
        publicKey = signingCertificate.getPublicKey();
    }


    @Test
    public void shouldParseApnicRpslObject() throws IOException {

        RpslObject rpslObject = new RpslObject(testSignedObject);
        assertEquals(rpslObject.getRpsl(), testSignedObject);

        Set<String> attributes = rpslObject.getAttributes();
        System.out.print(attributes);

        assertTrue(attributes.contains("remarks"));
    }

    @Test
    public void shouldValidateSignature() throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        RpslObject rpslObject = new RpslObject(testSignedObject);
        boolean result = rpslObject.validateSignature(publicKey);
        assertTrue(result);
    }

    @Test
    public void shouldValidateResources() throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        RpslObject rpslObject = new RpslObject(testSignedObject);
        boolean result = rpslObject.validateSignature(publicKey);
        assertTrue(result);
    }


}
