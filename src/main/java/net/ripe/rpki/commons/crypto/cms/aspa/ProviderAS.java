package net.ripe.rpki.commons.crypto.cms.aspa;

import lombok.*;
import lombok.experimental.Delegate;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;

import java.util.Objects;
import java.util.Optional;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProviderAS implements Comparable<ProviderAS> {
    @Delegate
    Asn providerAsn;

    @Override
    public int compareTo(ProviderAS that) {
        return this.providerAsn.compareTo(that.providerAsn);
    }
}
