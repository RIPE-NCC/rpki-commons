package net.ripe.commons.certification.util;

import static org.junit.Assert.*;

import org.junit.Test;


public class VersionedIdTest {

    @Test
    public void shouldDefaultToInitialVersion() {
        VersionedId subject = new VersionedId(9);
        assertEquals(9, subject.getId());
        assertEquals(VersionedId.INITIAL_VERSION, subject.getVersion());
    }
    
    @Test
    public void shouldHaveIdAndVersion() {
        VersionedId subject = new VersionedId(12, 32);
        assertEquals(12, subject.getId());
        assertEquals(32, subject.getVersion());
    }
    
    @Test
    public void testEquals() {
        assertEquals(new VersionedId(12, 32), new VersionedId(12, 32));
        assertEquals(new VersionedId(12, 32).hashCode(), new VersionedId(12, 32).hashCode());
        assertFalse(new VersionedId(12, 32).equals(new VersionedId(13, 32)));
        assertFalse(new VersionedId(12, 32).equals(new VersionedId(12, 33)));
    }

    @Test
    public void testToString() {
        assertEquals("12:32", new VersionedId(12, 32).toString());
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldFailToParseEmptyString() {
        VersionedId.parse("");
    }
    
    @Test(expected=IllegalArgumentException.class)
    public void shouldFailToParseNullString() {
        VersionedId.parse(null);
    }
    
    @Test
    public void shouldParseIdWithVersion() {
        assertEquals(new VersionedId(3, 24), VersionedId.parse("3:24"));
    }
    
    @Test
    public void shouldParseWithoutVersion() {
        assertEquals(new VersionedId(3, 0), VersionedId.parse("3"));
    }
    
}
