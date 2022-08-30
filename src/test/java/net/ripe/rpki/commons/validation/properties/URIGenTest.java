package net.ripe.rpki.commons.validation.properties;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.internal.generator.SimpleGenerationStatus;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class URIGenTest {

    @Test
    void generate() {
        URIGen uriGen = new URIGen();
        Random random = new Random();
        SourceOfRandomness r = new SourceOfRandomness(random);
        random.setSeed(1);

        System.out.println(uriGen.generate(r, null).toString());
        System.out.println(uriGen.generate(r, null).toString());
        System.out.println(uriGen.generate(r, null).toString());
    }
}