package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.collect.ImmutableSortedSet;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.Optional;

import static org.junit.Assert.*;


public class ASProviderAttestationCmsParserTest {

    @Test
    public void should_parse_aspa() throws IOException {
        String path = "src/test/resources/conformance/root/aspa-bm.asa";
        byte[] bytes = FileUtils.readFileToByteArray(new File(path));
        ValidationResult result = ValidationResult.withLocation("aspa-bm.asa");
        ASProviderAttestationCmsParser parser = new ASProviderAttestationCmsParser();
        parser.parse(result, bytes);

        assertFalse("" + result.getFailuresForAllLocations(), result.hasFailures());
        ASProviderAttestationCms aspa = parser.getASProviderAttestationCms();
        assertEquals(Asn.parse("AS65000"), aspa.getCustomerAsn());
        assertEquals(
            ImmutableSortedSet.<ProviderAS>naturalOrder()
                .add(new ProviderAS(Asn.parse("AS65001"), Optional.empty()))
                .add(new ProviderAS(Asn.parse("AS65002"), Optional.of(AddressFamily.IPV4)))
                .build(),
            aspa.getProviderASSet()
        );
    }
}
