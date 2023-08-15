package net.ripe.rpki.commons.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

public class BBNCertificateConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Disabled("Early ripe ncc ta certificates have crldp set")
    @Test
    public void shouldRejectSelfSignedCertificateWithCRLDP() throws IOException {
        // CRLDP is present in the trust anchor 6487#4.8.6
        boolean hasFailure = parseCertificate("badRootBadCRLDP.cer");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldRejectCertificateWithCRLDPWithReasonFieldNotOmitted() throws IOException {
        // CRL Dist Pt has reasons 6487#4.8.6
        boolean hasFailure = parseCertificate("root/badCertCRLDPReasons.cer");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldRejectCertificateWithCRLDPWithCrlIssuer() throws IOException {
        // CRL Dist Pt has CRL Issuer 6487#4.8.6
        boolean hasFailure = parseCertificate("root/badCertCRLDPCrlIssuer.cer");
        assertTrue(hasFailure);
    }

    @Test
    public void shouldRejectCertificateWithoutKeyUsageBit() throws  IOException {
        // 179 NoKeyUsage          # no key usage extension 6487#4.8,4.8.4
        assertTrue(parseCertificate("root/badCertNoKeyUsage.cer"));
    }

    @Test
    public void shouldRejectCertificateWithTwoKeyUsageBits() throws  IOException {
        // 180 2KeyUsage           # two key usage extensions 5280#4.2
        assertTrue(parseCertificate("root/badCert2KeyUsage.cer"));
    }

    @CsvSource({
            "127, KUsageExtra,          has disallowed key usage bit (nonRepudiation) 6487#4.8.4",
            "217, KUsageDigitalSig,     has disallowed key usage bit (digitalSignature) 6487#4.8.4",
            "128, KUsageNoCertSign,     lacks bit for signing certificates 6487#4.8.4",
            "129, KUsageNoCrit,         key usage extension not critical 6487#4.8.4",
            "131, KUsageNoCRLSign,      lacks bit for signing CRLs 6487#4.8.4"
    })
    @ParameterizedTest(name = "{displayName} - {0} {1} {2}")
    public void shouldRejectCertificateWithIncorrectKeyUsageBits(String testCasenumber, String testCaseFile, String testCaseDescription) throws IOException {
        final String fileName = String.format("root/badCert%s.cer", testCaseFile);

        assertTrue("Should reject certificate with " + testCaseDescription + " from " + fileName, parseCertificate(fileName));
    }

    private boolean certificateHasWarningOrFailure(String certificate) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, certificate);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        new X509ResourceCertificateParser().parse(result, encoded);
        return result.hasFailures() || result.hasWarnings();
    }

    private boolean parseCertificate(String certificate) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, certificate);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        new X509ResourceCertificateParser().parse(result, encoded);
        return result.hasFailures();
    }
}