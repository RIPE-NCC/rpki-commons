package net.ripe.rpki.commons.crypto.cms;

import com.google.common.io.Resources;
import net.ripe.rpki.commons.util.RepositoryObjectType;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.joda.time.DateTime;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class GenericRpkiSignedObjectParserTest {
    @Test
    void should_parse_aspa() throws IOException {
        GenericRpkiSignedObjectParser parser = parse("interop/aspa/draft-ietf-sidrops-profile-15-sample.asa");

        assertThat(parser.getRepositoryObjectType().get()).isEqualTo(RepositoryObjectType.Aspa);
        assertThat(parser.getSigningTime()).isEqualTo(DateTime.parse("2023-06-07T09:08:41+00:00"));
    }

    @Disabled("Our parser rejects GBR objects: corrupted stream - out of bounds length found: 115 >= 32")
    @Test
    void should_parse_gbr() throws IOException {
        GenericRpkiSignedObjectParser parser = parse("conformance/root/goodRealGbrNothingIsWrong.gbr");

        assertThat(parser.getRepositoryObjectType().get()).isEqualTo(RepositoryObjectType.Gbr);
        assertThat(parser.getSigningTime()).isEqualTo(DateTime.parse("2016-08-19T12:10:32+00:00"));
    }

    @Test
    void should_parse_manifest() throws IOException {
        GenericRpkiSignedObjectParser parser = parse("conformance/root/root.mft");

        assertThat(parser.getRepositoryObjectType().get()).isEqualTo(RepositoryObjectType.Manifest);
        assertThat(parser.getSigningTime()).isEqualTo(DateTime.parse("2013-10-28T21:24:39+00:00"));
    }

    @Test
    void should_parse_roa() throws IOException {
        GenericRpkiSignedObjectParser parser = parse("interop/rpkid-objects/nI2bsx18I5mlex8lBpY0WSJUYio.roa");

        assertThat(parser.getRepositoryObjectType().get()).isEqualTo(RepositoryObjectType.Roa);
        assertThat(parser.getSigningTime()).isEqualTo(DateTime.parse("2011-11-11T01:55:18+00:00"));
    }


    private GenericRpkiSignedObjectParser parse(String path) throws IOException {
        byte[] bytes = Resources.toByteArray(Resources.getResource(path));
        ValidationResult result = ValidationResult.withLocation(path);
        GenericRpkiSignedObjectParser parser = new GenericRpkiSignedObjectParser();
        parser.parse(result, bytes);

        assertThat(result.hasFailures()).isFalse();

        return parser;
    }
}
