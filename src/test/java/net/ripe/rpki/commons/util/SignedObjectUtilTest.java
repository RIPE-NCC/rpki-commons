package net.ripe.rpki.commons.util;

import com.google.common.io.Resources;
import net.ripe.rpki.commons.crypto.util.SignedObjectUtil;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SignedObjectUtilTest {
    @DisplayName("Should parse the file creation time from RPKI objects")
    @ParameterizedTest(name = "{index} => {0} filename={1} expected-creation-time={3} path={2}")
    @CsvSource({
            "ASPA, sample.asa, interop/aspa/GOOD-profile-15-draft-ietf-sidrops-profile-15-sample.asa, 2023-06-07T09:08:41Z",
            // GBR parser has issues
            // "GBR, sample.gbr, conformance/root/goodRealGbrNothingIsWrong.gbr, 2023-06-07T09:01:01Z",
            // router certificate case is missing due to lack of samples.
            "Manifest, sample.mft, conformance/root/root.mft, 2013-10-28T21:24:39Z",
            "ROA, sample.roa, interop/rpkid-objects/nI2bsx18I5mlex8lBpY0WSJUYio.roa, 2011-11-11T01:55:18Z",
            "'Generic signed object (that does not match object profile)', generic-signed-object.gbr, interop/aspa/BAD-profile-13-AS211321-profile-13.asa, 2021-11-11T11:19:00Z",
    })
    void shouldParseObject(String description, String fileName, String path, String modified) throws IOException, SignedObjectUtil.NoTimeParsedException {
        Instant creationTime = SignedObjectUtil.getFileCreationTime(URI.create(fileName), Resources.toByteArray(Resources.getResource(path)));

        assertThat(creationTime).isEqualTo(DateTime.parse(modified));
    }

    @Test
    void shouldThrowOnUnknown_payload() {
        assertThatThrownBy(() -> SignedObjectUtil.getFileCreationTime(URI.create("foo.cer"), new byte[] {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF}))
            .isInstanceOf(SignedObjectUtil.NoTimeParsedException.class);
    }
    @Test
    void shouldThrowOnUnknown_extension() {
        assertThatThrownBy(() -> SignedObjectUtil.getFileCreationTime(URI.create("foo.xxx"), Resources.toByteArray(Resources.getResource("interop/aspa/BAD-profile-13-AS211321-profile-13.asa"))))
                .isInstanceOf(SignedObjectUtil.NoTimeParsedException.class);
    }
}
