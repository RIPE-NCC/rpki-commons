package net.ripe.commons.certification.rsync;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

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
		rsync.addOptions(Arrays.asList(new String[] {"--version"}));

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
