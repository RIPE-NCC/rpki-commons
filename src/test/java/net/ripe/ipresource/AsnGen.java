package net.ripe.ipresource;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import net.ripe.ipresource.Asn;

/**
 * Automatically used by {@link com.pholser.junit.quickcheck.runner.JUnitQuickcheck} _only when in the same package as
 * tes.
 */
@SuppressWarnings("unused")
public class AsnGen extends Generator<Asn> {
    public AsnGen() {
        super(Asn.class);
    }

    @Override
    public Asn generate(SourceOfRandomness random, GenerationStatus status) {
        return new Asn(Integer.toUnsignedLong(random.nextInt()));
    }
}
