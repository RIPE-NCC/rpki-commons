package net.ripe.rpki.commons.crypto.cms.manifest;

import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import org.joda.time.DateTime;
import org.junit.runner.RunWith;

import java.math.BigInteger;

import static net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParserTest.TEST_KEY_PAIR;
import static net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParserTest.createValidManifestEECertificate;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitQuickcheck.class)
public class ManifestCMSBuilderPropertyTest {
    @Property
    public void buildEncodedParseCheck(byte[] content, BigInteger manifestNumber, Integer validityHours) {
        ManifestCmsBuilder builder = new ManifestCmsBuilder();
        builder.addFile("test.crl", content);
        builder.withManifestNumber(manifestNumber);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        builder.withCertificate(createValidManifestEECertificate(TEST_KEY_PAIR));
        DateTime start = DateTime.now();
        builder.withValidityPeriod(new ValidityPeriod(start, start.plusHours(Math.abs(validityHours))));
        ManifestCms manifestCms = builder.build(TEST_KEY_PAIR.getPrivate());

        ManifestCmsParser mftParser = new ManifestCmsParser();
        mftParser.parse("test.mft", manifestCms.getEncoded());
        assertTrue(mftParser.getManifestCms().containsFile("test.crl"));
    }

}

