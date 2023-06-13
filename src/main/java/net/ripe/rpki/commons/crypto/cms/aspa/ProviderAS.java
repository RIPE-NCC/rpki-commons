package net.ripe.rpki.commons.crypto.cms.aspa;

import lombok.NonNull;
import lombok.Value;
import lombok.experimental.Delegate;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;

import java.util.Objects;
import java.util.Optional;

@Value
public class ProviderAS implements Comparable<ProviderAS> {
    @Delegate
    @NonNull Asn providerAsn;

    @Override
    public int compareTo(ProviderAS that) {
        return this.providerAsn.compareTo(that.providerAsn);
    }
}
