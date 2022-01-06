package net.ripe.rpki.commons.crypto.cms.roa;

import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.generator.InRange;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;

import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsObjectMother.TEST_KEY_PAIR;
import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest.createCertificate;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitQuickcheck.class)
public class RoaCMSBuilderPropertyTest {

    @Property public void buildEncodedParseCheck(
            @InRange(min="1", max="4294967295")  long asNum,
            @InRange(min="12", max="24") Integer maxLength
    ){

            RoaPrefix TEST_IPV4_PREFIX_1 = new RoaPrefix(IpRange.parse("10.64.0.0/12"), maxLength);
            List<RoaPrefix> prefixes = new ArrayList<>();
            prefixes.add(TEST_IPV4_PREFIX_1);

            RoaCmsBuilder builder = new RoaCmsBuilder();
            builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
            builder.withCertificate(createCertificate(prefixes, TEST_KEY_PAIR));
            Asn asn = new Asn(asNum);
            builder.withAsn(asn);
            builder.withPrefixes(prefixes);
            RoaCms roaCms = builder.build(TEST_KEY_PAIR.getPrivate());

            RoaCmsParser roaParser = new RoaCmsParser();
            roaParser.parse("test.roa", roaCms.getEncoded());

            RoaCms parsedRoaCms = roaParser.getRoaCms();
            assertTrue(parsedRoaCms.getPrefixes().equals(prefixes));
            assertTrue(parsedRoaCms.getAsn().equals(asn));
    }


}

