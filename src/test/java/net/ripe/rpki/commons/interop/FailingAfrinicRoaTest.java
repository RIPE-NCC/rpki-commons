package net.ripe.rpki.commons.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

public class FailingAfrinicRoaTest {

    private static final String PATH_TO_OBJECTS = "src/test/resources/interop/misc-objects";

    @Test
    public void shouldParseAfrinicRoaWithSigningTimeOutsideOfCertificateValidityTime() throws IOException {
        byte[] encoded = Files.toByteArray(new File(PATH_TO_OBJECTS + "/6C76EDB2225D11E286C4BD8F7A2F2747.roa"));

        String location = "afrinic.roa";
        ValidationResult result = ValidationResult.withLocation(location);
        RoaCmsParser roaParser = new RoaCmsParser();

        roaParser.parse(result, encoded);

        assertFalse(result.hasFailures());
    }


}
