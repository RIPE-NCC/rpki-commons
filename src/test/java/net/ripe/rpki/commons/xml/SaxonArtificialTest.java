package net.ripe.rpki.commons.xml;

import net.sf.saxon.Version;
import org.junit.Test;

import static org.junit.Assert.*;

// This test exists only to prevent the Saxon dependency from being removed.
// It is needed at runtime by rpki-core.
public class SaxonArtificialTest {
    @Test
    public void testSaxonDependencyExists() {
        assertEquals("SAXON", Version.getProductName());
        assertNotNull(Version.getProductVersion());
        var majorVersion = extractMajorVersion(Version.getProductVersion());
        assertTrue("Expected Saxon version >= 12, but got " + majorVersion, majorVersion >= 12);
    }

    static int extractMajorVersion(String version) {
        String[] parts = version.split("\\.");
        return Integer.parseInt(parts[0]);
    }
}
