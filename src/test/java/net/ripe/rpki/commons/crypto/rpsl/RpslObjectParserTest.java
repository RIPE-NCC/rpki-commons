package net.ripe.rpki.commons.crypto.rpsl;

import com.google.common.io.Files;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.Set;

import static org.junit.Assert.*;

public class RpslObjectParserTest {

    private static final String PATH_TO_OBJECTS = "src/test/resources/apnic-rpsl-sig";

    @Test
    public void shouldParseApnicRpslObject() throws IOException {

        String rpsl = Files.toString(new File(PATH_TO_OBJECTS + "/rpsl-object.txt"), Charset.forName("UTF-8"));

        RpslObject rpslObject = new RpslObject(rpsl);
        assertEquals(rpslObject.getRpsl(), rpsl);

        Set<String> attributes = rpslObject.getAttributes();
        System.out.print(attributes);

        assertTrue(attributes.contains("remarks"));
    }


    @Test
    public void shouldValidateSignature() throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
        String rpsl = Files.toString(new File(PATH_TO_OBJECTS + "/rpsl-object.txt"), Charset.forName("UTF-8"));
        RpslObject rpslObject = new RpslObject(rpsl);
        boolean result = rpslObject.validateSignature(loadPublicKey());
        assertTrue(result);
    }


    private PublicKey loadPublicKey() throws IOException {
        String location = "apnic-ee-cert-for-rpsl-signature";
        ValidationResult result = ValidationResult.withLocation(location);

        RpslSigningCertificateParser parser = new RpslSigningCertificateParser();
        byte[] encoded = Files.toByteArray(new File(PATH_TO_OBJECTS + "/test.cer"));

        parser.parse(result, encoded);
        assertFalse(result.hasFailures());

        return parser.getRpslSigningCertificate().getPublicKey();
    }

}
