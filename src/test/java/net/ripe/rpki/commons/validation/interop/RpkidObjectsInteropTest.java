package net.ripe.rpki.commons.validation.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

public class RpkidObjectsInteropTest {

    private static final String PATH_TO_RPKID_OBJECTS = "src/test/resources/interop/rpkid-objects/";

    @Test
    public void shouldValidateRoa() throws IOException {
        byte[] encoded = Files.toByteArray(new File(PATH_TO_RPKID_OBJECTS + "nI2bsx18I5mlex8lBpY0WSJUYio.roa"));

        String location = "unknown.roa";
        RoaCmsParser parser = new RoaCmsParser();
        parser.parse(location, encoded);
        ValidationResult validationResult = parser.getValidationResult();

        assertFalse(validationResult.hasFailures());

        RoaCms roa = parser.getRoaCms();
        assertNotNull(roa.getContentType());
    }


}
