package net.ripe.rpki.commons.crypto;

import org.jetbrains.annotations.NotNull;

public record CertificateRepositoryObjectFile<T extends CertificateRepositoryObject>(
    @NotNull Class<T> expectedType,
    @NotNull String name,
    @NotNull byte[] content
) {
}
