package net.ripe.rpki.commons.ccr.asn1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HexFormat;
import java.util.List;

class Sha256DigestTest {
    @ParameterizedTest
    @ValueSource(strings = {
        "000433534696E98654369C0793C4BE5FDB0CFA9D69072B28F5615DE794DA3DFD",
        "000000000000000000000000748537bbcdea94b590318fd5c07aa87cf1664e0b",
    })
    void should_preserve_hash_value(String hex) {
        var bytes = HexFormat.of().parseHex(hex);
        var hash =  Sha256Digest.from(bytes);
        Assertions.assertEquals(
            hex.toLowerCase(),
            HexFormat.of().formatHex(hash.octets()),
            "Invalid re-encoding of hash: %s turned into %s".formatted(hex.toLowerCase(), HexFormat.of().formatHex(hash.octets()))
        );
    }

    @Test
    void should_sort_by_integer_value() {
        var zero = Sha256Digest.from(new byte[32]);
        var one = Sha256Digest.from(new byte[] { 1 });

        var hashes = List.of(one, zero);
        var sorted = hashes.stream().sorted().toList();
        Assertions.assertEquals(List.of(zero, one), sorted);
    }

    @Test
    void should_sort_live_example() {
        var h = Sha256Digest.from(HexFormat.of().parseHex("0001711878098cb6ab0282cde9a5780724dace9a8736b438c438dce5e5d142b6"));
        var c = Sha256Digest.from(HexFormat.of().parseHex("8080d8c56853fe4f185c3cacbd4b6804aea34c4f9ad3658f009e1842243749be"));
        var hashes = List.of(h, c);
        var sorted = hashes.stream().sorted().toList();
        Assertions.assertEquals(List.of(h, c), sorted);
    }
}
