package net.ripe.rpki.commons.crypto.cms.aspa;

import lombok.NonNull;
import lombok.Value;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;

import java.util.Objects;
import java.util.Optional;

@Value
public class ProviderAS implements Comparable<ProviderAS> {
    @NonNull Asn providerAsn;
    @NonNull Optional<AddressFamily> afiLimit;

    @Override
    public int compareTo(ProviderAS that) {
        int rc = this.providerAsn.compareTo(that.providerAsn);
        if (rc != 0) {
            return rc;
        }

        if (Objects.equals(this.afiLimit, that.afiLimit)) {
            return 0;
        } else if (!this.afiLimit.isPresent()) {
            return -1;
        } else if (!that.afiLimit.isPresent()) {
            return 1;
        } else {
            return this.afiLimit.get().compareTo(that.afiLimit.get());
        }
    }
}
