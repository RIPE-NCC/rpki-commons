package net.ripe.rpki.commons.xml;

import net.sf.saxon.Version;
import org.junit.Test;

import static org.junit.Assert.*;

// This test exists only to prevent the Saxon dependency from being removed.
// It is needed at runtime by rpki-core.
public class SaxonDependencyIsPresentTest {
    @Test
    public void testSaxonDependencyExists() {
        assertEquals("SAXON", Version.getProductName());
        var saxonVersion = Version.getProductVersion();
        assertNotNull(saxonVersion);
        var majorVersion = Integer.parseInt(saxonVersion.split("\\.")[0]);
        assertTrue("Expected Saxon version >= 12, but got " + majorVersion, majorVersion >= 12);
    }

}
