package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.io.Resources;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Optional;

import static net.ripe.rpki.commons.validation.ValidationString.ASPA_CONTENT_TYPE;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

public class AspaCmsParserTest {

    @Test
    public void should_parse_aspa_rpkimancer() throws IOException {
        AspaCms aspa = parseValidAspa("interop/aspa/aspa-rpkimancer.asa");
        assertThat(aspa.getCustomerAsn()).isEqualTo(Asn.parse("AS65000"));
        assertThat(aspa.getProviderASSet()).containsExactly(
                        new ProviderAS(Asn.parse("AS65001"), Optional.empty()),
                        new ProviderAS(Asn.parse("AS65002"), Optional.of(AddressFamily.IPV4))
        );
    }

    @Test
    public void should_parse_aspa_krill() throws IOException {
        AspaCms aspa = parseValidAspa("interop/aspa/AS211321.asa");
        assertThat(aspa.getCustomerAsn()).isEqualTo(Asn.parse("AS211321"));
        assertThat(aspa.getProviderASSet()).containsExactly(
                        new ProviderAS(Asn.parse("AS65000"), Optional.empty()),
                        new ProviderAS(Asn.parse("AS65001"), Optional.of(AddressFamily.IPV4)),
                        new ProviderAS(Asn.parse("AS65002"), Optional.of(AddressFamily.IPV6))
        );
    }

    private AspaCms parseValidAspa(String path) throws IOException {
        byte[] bytes = Resources.toByteArray(Resources.getResource(path));
        ValidationResult result = ValidationResult.withLocation(path);
        AspaCmsParser parser = new AspaCmsParser();
        parser.parse(result, bytes);

        assertThat(result.getFailuresForAllLocations())
                .withFailMessage(() -> "" + result.getFailuresForAllLocations())
                .isEmpty();

        AspaCms aspa = parser.getAspa();
        return aspa;
    }

    @Test
    public void parseAspa_wrong_file_type() throws IOException {
        AspaCmsParser parser = new AspaCmsParser();
        ValidationResult result = ValidationResult.withLocation("goodROAASIDZero.roa");
        parser.parse(result, Resources.toByteArray(Resources.getResource("conformance/root/goodROAASIDZero.roa")));

        assertThat(result.hasFailures()).isTrue();
        assertThat(result.getFailuresForAllLocations()).anyMatch(check -> ASPA_CONTENT_TYPE.equals(check.getKey()));
    }
}
