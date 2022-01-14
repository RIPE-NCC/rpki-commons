package net.ripe.rpki.commons.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

public class BBNCrlConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Test
    public void shouldParseCrlWith2CrlNumbers() throws IOException {
        //has 2 CRL numbers 6487#errata
        boolean hasFailure = parseCrl("root/CRL2CRLNums/badCRL2CRLNums.crl");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseCrlWithVersion0() throws IOException {
        // CRL version v1 (integer value 0) 6487#5
        boolean hasFailure = parseCrl("root/CRLVersion0/badCRLVersion0.crl");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseCrlWithVersion2() throws IOException {
        // CRL version v3 (integer value 2) 6487#5
        boolean hasFailure = parseCrl("root/CRLVersion2/badCRLVersion2.crl");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseCrlWithWrongSignatureAlgorithmIdInToBeSigned() throws IOException {
        // wrong signature algorithm ID in toBeSigned 6487#5 6485#2
        boolean hasFailure = parseCrl("root/CRLSigAlgInner/badCRLSigAlgInner.crl");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldParseCrlWithWrongOuterSignatureAlgorithmId() throws IOException {
        // wrong outer signature algorithm ID 6487#5 6485#2
        boolean hasFailure = parseCrl("root/CRLSigAlgOuter/badCRLSigAlgOuter.crl");
        assertTrue(hasFailure);
    }

    private boolean parseCrl(String crl) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, crl);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        X509Crl.parseDerEncoded(encoded, result);
        return result.hasFailures();
    }
}
