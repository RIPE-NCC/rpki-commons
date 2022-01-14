package net.ripe.rpki.commons.rsync;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;


public class RsyncTest {

    @Test
    public void shouldExecuteCommand() {
        Rsync rsync = new Rsync();
        rsync.addOptions("--version");

        assertFalse(rsync.isCompleted());
        assertNull(rsync.getException());
        assertNull(rsync.getErrorLines());
        assertNull(rsync.getOutputLines());

        int exitStatus = rsync.execute();

        assertTrue(exitStatus == 0);
        assertTrue(rsync.isCompleted());
        assertNull(rsync.getException());
        assertNotNull(rsync.getErrorLines());
        assertTrue(rsync.getErrorLines().length == 0);
        assertNotNull(rsync.getOutputLines());
        assertTrue(rsync.getOutputLines().length > 0);
    }

    @Test
    public void shouldMeasureElapsedTime() {
        Rsync rsync = new Rsync();
        rsync.addOptions("--version");

        rsync.execute();

        // Let's hope the system is not too fast.
        assertTrue(rsync.elapsedTime() > 0);
    }

    @Test
    public void shouldFailOnInvalidOption() {
        Rsync rsync = new Rsync();
        rsync.addOptions("--invalid_option");

        rsync.execute();

        assertTrue(rsync.getExitStatus() != 0);
        assertTrue(rsync.isCompleted());
        assertNull(rsync.getException());
        assertNotNull(rsync.getErrorLines());
        assertTrue(rsync.getErrorLines().length > 0);
        assertNotNull(rsync.getOutputLines());
        assertTrue(rsync.getOutputLines().length == 0);
    }

    @Test
    public void shouldResetProperly() {
        Rsync rsync = new Rsync();
        rsync.addOptions(Collections.singletonList("--version"));

        assertFalse(rsync.isCompleted());
        assertNull(rsync.getException());
        assertNull(rsync.getErrorLines());
        assertNull(rsync.getOutputLines());

        int exitStatus = rsync.execute();

        assertTrue(exitStatus == 0);
        assertTrue(rsync.isCompleted());
        assertNull(rsync.getException());
        assertNotNull(rsync.getErrorLines());
        assertTrue(rsync.getErrorLines().length == 0);
        assertNotNull(rsync.getOutputLines());
        assertTrue(rsync.getOutputLines().length > 0);

        rsync.reset();

        assertFalse(rsync.isCompleted());
        assertNull(rsync.getException());
        assertNull(rsync.getErrorLines());
        assertNull(rsync.getOutputLines());
    }
}
