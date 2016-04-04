package net.ripe.rpki.commons.crypto.rpsl;

import com.google.common.io.Files;
import net.ripe.rpki.commons.validation.ValidationResult;

import org.junit.Test;

import java.io.File;
import java.nio.charset.Charset;
import java.io.IOException;
import java.util.Set;

import static org.junit.Assert.*;

public class RpslObjectParserTest {

    private static final String PATH_TO_OBJECTS = "src/test/resources/apnic-rpsl-sig";

    @Test
    public void shouldParseApnicRpslObject() throws IOException {

        String rpsl = Files.toString(new File(PATH_TO_OBJECTS + "/rpsl-object.txt"), Charset.forName("UTF-8"));

        String location = "rpsl-object.txt";
        ValidationResult result = ValidationResult.withLocation(location);

        RpslObjectParser subject = new RpslObjectParser();

        subject.parse(result, rpsl);

        RpslObject rpslObject = subject.getRpslObject();
        assertEquals(rpslObject.getRpsl(), rpsl);

        Set<String> attributes = rpslObject.getAttributes();
        System.out.print(attributes);

        assertTrue(attributes.contains("remarks"));
    }

}