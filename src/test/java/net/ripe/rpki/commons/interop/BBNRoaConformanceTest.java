package net.ripe.rpki.commons.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

public class BBNRoaConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Test
    public void shouldParseRoaWithMissingSignature() throws IOException {
        // no signature 6488#2.1.6.6
        boolean hasFailure = parseRoa("root/badCMSSigInfoNoSig.roa");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseRoaWithNoSignerInfo() throws IOException {
        // empty set of SignerInfos 6488#2.1
        boolean hasFailure = parseRoa("root/badCMSNoSigInfo.roa");
        assertTrue(hasFailure);
    }

    private boolean parseRoa(String roa) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, roa);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        new RoaCmsParser().parse(result, encoded);
        return result.hasFailures();
    }
}
