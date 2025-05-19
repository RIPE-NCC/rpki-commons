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
    void generateTest() {
        String[] schemas = { "rsync" };
        URIGen uriGen = new URIGen(schemas);

        Random random = new Random();
        SourceOfRandomness r = new SourceOfRandomness(random);

        for (int i = 0; i < 1000; i++) {
            URI uri = uriGen.generate(r, null);
            assertNotNull(uri);
            assertNotNull(uri.getHost());
            assertNotNull(uri.getScheme());
            assertNotNull(uri.getPath());
            assertEquals("rsync", uri.getScheme());
        }
    }
}