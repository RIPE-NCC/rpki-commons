package net.ripe.rpki.commons.crypto.cms.manifest;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.time.Instant;

public record ManifestCmsGeneralInfo(int version, @NotNull BigInteger number, @NotNull Instant thisUpdateTime, @NotNull Instant nextUpdateTime, @NotNull String fileHashAlgorithm) {
}
