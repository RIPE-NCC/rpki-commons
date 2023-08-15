package net.ripe.rpki.commons.crypto.cms.aspa;

import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;
import java.util.Optional;

public record ProviderAS(@NotNull Asn providerAsn,
                         @NotNull Optional<AddressFamily> afiLimit) implements Comparable<ProviderAS> {
    @Override
    public int compareTo(ProviderAS that) {
        int rc = this.providerAsn.compareTo(that.providerAsn);
        if (rc != 0) {
            return rc;
        }

        if (Objects.equals(this.afiLimit, that.afiLimit)) {
            return 0;
        } else if (this.afiLimit.isEmpty()) {
            return -1;
        } else if (that.afiLimit.isEmpty()) {
            return 1;
        } else {
            return this.afiLimit.get().compareTo(that.afiLimit.get());
        }
    }
}
