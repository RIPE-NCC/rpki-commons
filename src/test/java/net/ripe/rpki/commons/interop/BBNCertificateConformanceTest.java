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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class BBNCertificateConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Disabled("Early ripe ncc ta certificates have crldp set")
    @Test
    public void shouldRejectSelfSignedCertificateWithCRLDP() throws IOException {
        // CRLDP is present in the trust anchor 6487#4.8.6
        boolean hasFailure = parseCertificate("badRootBadCRLDP.cer");
        assertThat(hasFailure).isTrue();
    }

    @Test
    public void shouldRejectCertificateWithCRLDPWithReasonFieldNotOmitted() throws IOException {
        // CRL Dist Pt has reasons 6487#4.8.6
        boolean hasFailure = parseCertificate("root/badCertCRLDPReasons.cer");
        assertThat(hasFailure).isTrue();
    }

    @Test
    public void shouldRejectCertificateWithCRLDPWithCrlIssuer() throws IOException {
        // CRL Dist Pt has CRL Issuer 6487#4.8.6
        boolean hasFailure = parseCertificate("root/badCertCRLDPCrlIssuer.cer");
        assertThat(hasFailure).isTrue();
    }

    @Test
    public void shouldRejectCertificateWithoutKeyUsageBit() throws  IOException {
        // 179 NoKeyUsage          # no key usage extension 6487#4.8,4.8.4
        assertThat(parseCertificate("root/badCertNoKeyUsage.cer")).isTrue();
    }

    @Test
    public void shouldRejectCertificateWithTwoKeyUsageBits() throws  IOException {
        // 180 2KeyUsage           # two key usage extensions 5280#4.2
        assertThat(parseCertificate("root/badCert2KeyUsage.cer")).isTrue();
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

        assertThat(parseCertificate(fileName))
                .isTrue()
                .withFailMessage("Should reject certificate with " + testCaseDescription + " from " + fileName);
    }

    @CsvSource({
            "218, ResourcesIP6Inherit, # (good) inherit IPv6 resources only, others explicit 6487#4.8.10",
            "219, ResourcesIP4Inherit, # (good) inherit IPv4 resources only, others explicit 6487#4.8.10",
            "220, ResourcesASInherit, # (good) inherit AS resources only, others explicit 6487#4.8.11",
            "221, ResourcesAllInherit, # (good) inherit all resources 6487#4.8.10",
            "222, ResourcesIP6InhOnly, # (good) inherit IPv6 resources only, others not present 6487#4.8.10",
            "223, ResourcesIP4InhOnly, # (good) inherit IPv4 resources only, others not present 6487#4.8.10",
            "224, ResourcesASInhOnly, # (good) inherit AS resources only, others not present 6487#4.8.11",
    })
    @ParameterizedTest(name = "{displayName} - {0} {1} {2}")
    public void shouldAcceptCertificateWithResourceExtension(String testCasenumber, String testCaseFile, String testCaseDescription) throws IOException {
        final String fileName = String.format("root/goodCert%s.cer", testCaseFile);

        assertThat(parseCertificate(fileName))
                .isFalse()
                .withFailMessage("Should accept certificate with " + testCaseDescription + " from " + fileName);
    }

    @CsvSource({
        "138, ResourcesASNoCrit, # AS number extension not critical 6487#4.8.11",
        "139, ResourcesBadAFI, # invalid IP address family 6487#4.8.10, IANA address-family-numbers",
        "140, ResourcesBadASOrder, # AS numbers out of order 3779 (but full set is pending)",
        "141, ResourcesBadV4Order, # IPv4 addresses out of order 3779 (but full set is pending)",
        "142, ResourcesBadV6Order, # IPv6 addresses out of order 3779 (but full set is pending)",
        "143, ResourcesIPNoCrit, # IP address extension not critical 6487#4.8.10",
        "144, ResourcesNone, # neither AS nor IP 3779 extensions 6487#4.8.10",
        "192, ResourcesIPEmpty, # empty set of IP addresses 6487#4.8.10",
        "193, ResourcesASEmpty, # empty set of AS numbers 6487#4.8.11",
        "145, ResourcesSAFI, # IP addresses has SAFI digit 6487#4.8.10",
    })
    @ParameterizedTest(name = "{displayName} - {0} {1} {2}")
    public void shouldRejectCertificateWithInvalidResourceExtension(String testCasenumber, String testCaseFile, String testCaseDescription) throws IOException {
        final String fileName = String.format("root/badCert%s.cer", testCaseFile);

        assertThatThrownBy(() -> parseCertificate(fileName))
                .isInstanceOfAny(IllegalArgumentException.class, IllegalStateException.class)
                .withFailMessage("Should reject certificate with " + testCaseDescription + " from " + fileName);
    }

    private boolean certificateHasWarningOrFailure(String certificate) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, certificate);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        var parser = new X509ResourceCertificateParser();
        parser.parse(result, encoded);
        // Trigger some lazy parsing
        parser.getCertificate();
        return result.hasFailures() || result.hasWarnings();
    }

    private boolean parseCertificate(String certificate) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, certificate);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        var parser = new X509ResourceCertificateParser();
        parser.parse(result, encoded);

        parser.getCertificate();
        return result.hasFailures();
    }
}