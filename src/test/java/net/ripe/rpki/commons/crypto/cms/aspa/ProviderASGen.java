package net.ripe.rpki.commons.crypto.cms.aspa;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;

import java.util.Arrays;
import java.util.Optional;

/**
 * Automatically used by {@link com.pholser.junit.quickcheck.runner.JUnitQuickcheck}.
 */
@SuppressWarnings("unused")
public class ProviderASGen extends Generator<ProviderAS> {
    public ProviderASGen() {
        super(ProviderAS.class);
    }

    @Override
    public ProviderAS generate(SourceOfRandomness random, GenerationStatus status) {
        Asn providerAsn = new Asn(Integer.toUnsignedLong(random.nextInt()));
        Optional<AddressFamily> afiLimit = random.choose(Arrays.asList(Optional.empty()));
        return new ProviderAS(providerAsn, afiLimit);
    }
}
