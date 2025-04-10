package net.ripe.rpki.commons.xml;

import net.sf.saxon.Version;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

// This test exists only to prevent the Saxon dependency from being removed.
// It is needed at runtime by rpki-core.
public class SaxonArtificialTest {
    @Test
    public void testSaxonDependencyExists() {
        assertEquals("SAXON", Version.getProductName());
    }
}
