package net.ripe.rpki.commons.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertTrue;

// CMS signed objects, generic (using ROAs)
public class BBNCMSConformanceTest {
    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @CsvSource({
            "512, ContentType,              # wrong content type 6488#2",
            "513, NoCerts,                  # no certificate 6488#2.1",
            "514, 2Certs,                   # two certificates 6488#2.1",
            "515, Version2,                 # version 2 6488#2.1.1",
            "516, Version4,                 # version 4 6488#2.1.1",
            "517, DigestAlgSameWrong,       # wrong digest algorithm (same in both places) 6488#2.1.2 6485#2",
            "546, DigestAlgWrongOuter,      # wrong digest algorithm (in SignedData) 6488#2.1.2 6485#2",
            "519, NoDigestAlgs,             # no digest algorithm 6488#2.1.2",
            "520, HasCRL,                   # has a CRL 6488#2.1.5",
            "521, NoSigInfo,                # empty set of SignerInfos 6488#2.1",
            "721, 2SigInfo,                 # multiple SignerInfo objects in set 6488#2.1",
            "523, SigInfoVersion,           # wrong Signer Info version (2) 6488#2.1.6.1",
            "524, SigInfoVersion4,          # wrong Signer Info version (4) 6488#2.1.6.1",
            "525, SigInfoNoSid,             # no Signer Identifier 6488#2.1.6.2",
            "527, SigInfoBadSid,            # bad Signer Identifier (wrong SKI) 6488#2.1.6.2",
            "528, SigInfoHashAlg,           # wrong digest algorithm (in SignerInfo) 6488#2.1.6.3 6485#2",
            "529, SigInfoNoAttrs,           # no set of attributes in SignerInfo 6488#2.1.6.4",
            "530, SigInfoAttrsNoContType,   # no content type in Signer Info 6488#2.1.6.4.1",
            "531, SigInfoAttrsContTypeOid,  # content type OID does not match eContentType 6488#2.1.6.4.1",
            "533, SigInfoAttrsNoMsgDigest,  # no message digest 6488#2.1.6.4.2",
            "548, SigInfoAttrsWrongDigest,  # incorrect SHA-256 message digest 6488#2.1.6.4.2",
            "534, SigInfoAttrs2ContType,    # duplicate content type attributes 6488#2.1.6.4",
            "535, SigInfoAttrs2MsgDigest,   # duplicate digest attributes 6488#2.1.6.4",
            "536, SigInfoAttrs2SigTime,     # duplicate signing time attributes 6488#2.1.6.4",
            "537, SigInfoAttrs2BinSigTime,  # duplicate binary signing time attributes 6488#2.1.6.4",
            "549, SigInfoAttrsContType2Val,    # duplicate content type attribute values 6488#2.1.6.4",
            "564, SigInfoAttrsMsgDigest2Val,   # duplicate digest attribute values 6488#2.1.6.4",
            "565, SigInfoAttrsSigTime2Val,     # duplicate signing time attribute values 6488#2.1.6.4",
            "566, SigInfoAttrsBinSigTime2Val,  # duplicate binary signing time attribute values 6488#2.1.6.4",
            "567, SigInfoAttrsContType0Val,    # empty set of content type attribute values 6488#2.1.6.4",
            "568, SigInfoAttrsMsgDigest0Val,   # empty set of digest attribute values 6488#2.1.6.4",
            "570, SigInfoAttrsSigTime0Val,     # empty set of signing time attribute values 6488#2.1.6.4",
            "569, SigInfoAttrsBinSigTime0Val,  # empty set of binary signing time attribute values 6488#2.1.6.4",
            "538, SigInfoUnSigAttrs,        # has unsigned attribute 6488#2.1.6.7",
            "539, SigInfoNoSig,             # no signature 6488#2.1.6.6",
            "540, SigInfo2Sig,              # has two signatures 6488#2.1.6.6",
            "571, SigInfoBadSigVal,         # incorrect signature 6488#2.1.6.6",
            "543, SigInfoNoHashAlg,         # had no hash algorithm 6488#2.1.6.3"
    })
    @ParameterizedTest(name = "{displayName} - {0} {1} {2}")
    public void testGenericCMSSignedObject(String testNumber, String testCaseFile, String testCaseDescription) throws IOException {
        final String fileName = String.format("root/badCMS%s.roa", testCaseFile);

        assertTrue("Should reject certificate with " + testCaseDescription + " from " + fileName, parseCertificate(fileName));
    }

    @CsvSource({
            "572, badEEHasBasicConstraints,      basic constraints extension present 6487#4.8.1",
            "575, badEEHasCABasicConstraint,     basic constraints extension present with CA bool set to true 6487#4.8.1",
            "574, badEEKeyUsageHasKeyCertSign,   KU has digitalSignature and keyCertSign but no CA basic constraint 6487#4.8.4",
            "576, badEEKeyUsageHasKeyCertSignCABool,   KU has digitalSignature and keyCertSign and CA basic constraint 6487#4.8.4"
    })
    @ParameterizedTest(name = "{displayName} - {0} {1} {2}")
    public void shouldRejectCMSWithIncorrectBasicConstrainsOrKU(String testCasenumber, String testCaseFile, String testCaseDescription) throws IOException {
        final String fileName = String.format("root/%s.roa", testCaseFile);

        assertTrue("Should reject EE certificate with " + testCaseDescription + " from " + fileName, parseCertificate(fileName));
    }


    @Disabled("These checks are not implemented yet.")
    @CsvSource({
            "518, 2DigestAlgs,              # two digest algorithms 6488#2.1.2",
            "526, SigInfoWrongSid,          # wrong choice of Signer Identifier 6488#2.1.6.2",
            "542, SigInfoWrongSigAlg,       # has wrong signature algorithm 6488#2.1.6.5 6485#2",
            "722, SigInfoForbiddenAttr,     # extra - forbidden attribute 6488#2.1.6.4",
    })
    @ParameterizedTest(name = "{displayName} - {0} {1} {2}")
    public void testGenericCMSSignedObject_ignored(String testNumber, String testCaseFile, String testCaseDescription) throws IOException {
        final String fileName = String.format("root/badCMS%s.roa", testCaseFile);

        assertTrue("Should reject certificate with " + testCaseDescription + " from " + fileName, parseCertificate(fileName));
    }

    private boolean parseCertificate(String certificate) throws IOException {
        File file = new File(PATH_TO_BBN_OBJECTS, certificate);
        byte[] encoded = Files.toByteArray(file);
        ValidationResult result = ValidationResult.withLocation(file.getName());
        new RoaCmsParser().parse(result, encoded);

        result.getFailuresForAllLocations().stream()
                .forEach(failure -> System.out.println("[failure]: " + failure.toString()));
        result.getWarnings().stream()
                .forEach(warning -> System.out.println("[warning]: " + warning.toString()));


        return result.hasFailures();
    }
}
