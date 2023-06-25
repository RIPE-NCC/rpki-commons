package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.io.Resources;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Optional;

import static net.ripe.rpki.commons.validation.ValidationString.ASPA_CONTENT_TYPE;
import static net.ripe.rpki.commons.validation.ValidationString.ASPA_VERSION;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

class AspaCmsParserTest {

    @Test
    void should_parse_draft15_aspa() throws IOException {
        AspaCms aspa = parseValidAspa("interop/aspa/GOOD-profile-15-draft-ietf-sidrops-profile-15-sample.asa");
        assertThat(aspa.getCustomerAsn()).isEqualTo(Asn.parse("AS15562"));
        assertThat(aspa.getVersion()).isEqualTo(1);
        assertThat(aspa.getProviderASSet()).containsExactly(
                        Asn.parse("AS2914"),
                        Asn.parse("AS8283"),
                        Asn.parse("AS51088"),
                        Asn.parse("206238")
        );
    }

    @Test
    void should_parse_draft15_rpki_commons_object() throws IOException {
        AspaCms aspa = parseValidAspa("interop/aspa/GOOD-profile-15-rpki-commons-propertytest-sample.asa");
        assertThat(aspa.getVersion()).isEqualTo(1);
    }
    
    @Test
    void should_accept_apnic_test_aspa_v1() throws IOException {
        AspaCms aspa = parseValidAspa("interop/aspa/GOOD-profile-15-APNIC-rpki-aspa-demo-AS1000.asa");
        assertThat(aspa.getCustomerAsn()).isEqualTo(Asn.parse("AS1000"));
        assertThat(aspa.getVersion()).isEqualTo(1);
        assertThat(aspa.getProviderASSet()).containsExactly(
                        Asn.parse("AS1025")
        );
    }

    @Test
    void should_reject_apnic_test_aspa_WRONG_VERSION() throws IOException {
        AspaCmsParser parser = new AspaCmsParser();
        ValidationResult result = ValidationResult.withLocation("BAD-profile-15-APNIC-rpki-aspa-demo-AS1000.asa");
        parser.parse(result, Resources.toByteArray(Resources.getResource("interop/aspa/BAD-profile-15-APNIC-rpki-aspa-demo-AS1000.asa")));

        AssertionsForClassTypes.assertThat(result.hasFailures()).isTrue();
        assertThat(result.getFailuresForAllLocations()).anyMatch(check -> ASPA_VERSION.equals(check.getKey()));
    }

    @Test
    void parseAspa_wrong_profile_version() throws IOException {
        AspaCmsParser parser = new AspaCmsParser();
        ValidationResult result = ValidationResult.withLocation("BAD-profile-13-AS211321-profile-13.asa");
        parser.parse(result, Resources.toByteArray(Resources.getResource("interop/aspa/BAD-profile-13-AS211321-profile-13.asa")));

        assertThat(result.hasFailures()).isTrue();
        assertThat(result.getFailuresForAllLocations()).anyMatch(check -> ASPA_VERSION.equals(check.getKey()));
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
    void parseAspa_wrong_file_type() throws IOException {
        AspaCmsParser parser = new AspaCmsParser();
        ValidationResult result = ValidationResult.withLocation("goodROAASIDZero.roa");
        parser.parse(result, Resources.toByteArray(Resources.getResource("conformance/root/goodROAASIDZero.roa")));

        assertThat(result.hasFailures()).isTrue();
        assertThat(result.getFailuresForAllLocations()).anyMatch(check -> ASPA_CONTENT_TYPE.equals(check.getKey()));
    }
}
