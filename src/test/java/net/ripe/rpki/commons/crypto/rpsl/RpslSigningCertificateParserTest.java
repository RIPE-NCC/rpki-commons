package net.ripe.rpki.commons.crypto.rpsl;

import com.google.common.io.Files;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RpslSigningCertificateParserTest {

    private static final String PATH_TO_OBJECTS = "src/test/resources/apnic-rpsl-sig";

    RpslSigningCertificateParser subject = new RpslSigningCertificateParser();

    @Test
    public void shouldParseApnicCertificate() throws IOException {
        byte[] encoded = Files.toByteArray(new File(PATH_TO_OBJECTS + "/NoMuNJdN_LsKjdttcwvbErnVru8.cer"));
        String location = "apnic-ee-cert-for-rpsl-signature";
        ValidationResult result = ValidationResult.withLocation(location);

        subject.parse(result, encoded);
        assertFalse(result.hasFailures());
    }

}