package net.ripe.rpki.commons.validation.properties;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import net.ripe.ipresource.IpResource;

public class IpResourceGen extends Generator<IpResource> {

    public IpResourceGen() {
        super(IpResource.class);
    }

    @Override
    public IpResource generate(SourceOfRandomness sourceOfRandomness, GenerationStatus generationStatus) {
        return ResourceGenerator.generateIpResource(sourceOfRandomness);
    }

}
