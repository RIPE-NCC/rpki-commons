package net.ripe.rpki.commons.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.File;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class BBNRoaConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Test
    public void shouldParseRoaWithMissingSignature() throws IOException {
        // no signature 6488#2.1.6.6
        boolean hasFailure = parseRoa("root/badCMSSigInfoNoSig.roa");
        assertThat(hasFailure).isTrue();
    }

    @Test
    public void shouldParseRoaWithNoSignerInfo() throws IOException {
        // empty set of SignerInfos 6488#2.1
        boolean hasFailure = parseRoa("root/badCMSNoSigInfo.roa");
        assertThat(hasFailure).isTrue();
    }

    /**
     * Apply a number of test cases for version.
     *
     * Note that in these objects version is <emph>implicit</emph> not <emph>explicit</emph> as required.
     */
    @CsvSource({
        "557, VersionV1Explicit, # explicit V1 version (int 0) applied before signature 6482#3",
        "558, VersionV1ExplicitBadSig, # explicit V1 version (int 0) applied after signature 6482#3",
        "559, VersionV2, # Version V2 (int 1) 6482#3.1"
    })
    @ParameterizedTest(name = "{displayName} - {0} {1} {2}")
    public void shouldRejectBadRoaObject(String testNumber, String testCaseFile, String testCaseDescription) throws IOException {
        final String fileName = String.format("root/badROA%s.roa", testCaseFile);

        assertThat(parseRoa(fileName)).isTrue()
                .withFailMessage("[" + testNumber + "] Should reject certificate with " + testCaseDescription + " from " + fileName);
    }

    private boolean parseRoa(String roa) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, roa);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        new RoaCmsParser().parse(result, encoded);
        return result.hasFailures();
    }
}
