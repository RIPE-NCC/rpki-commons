package net.ripe.commons.certification.rsync;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.Test;

public class CommandTest {

	private static final String COMMAND = "whoami";


	@Test
	public void shouldExecuteCommand() {
		Command cmd = new Command(COMMAND);

		assertTrue(cmd.getExitStatus() == Command.NOT_EXECUTED);
		assertFalse(cmd.wasStarted());
		assertFalse(cmd.isCompleted());
		assertNull(cmd.getException());
		assertNull(cmd.getErrorLines());
		assertNull(cmd.getErrors());
		assertNull(cmd.getOutputLines());
		assertNull(cmd.getOutputs());

		cmd.execute();

		int exitStatus = cmd.getExitStatus();
		assertTrue(exitStatus == 0);
		assertTrue(cmd.wasStarted());
		assertTrue(cmd.isCompleted());
		assertNull(cmd.getException());
		assertNotNull(cmd.getErrorLines());
		assertTrue(cmd.getErrorLines().length == 0);
		assertNotNull(cmd.getErrors());
		assertTrue(cmd.getErrors().size() == 0);
		assertNotNull(cmd.getOutputLines());
		assertTrue(cmd.getOutputLines().length > 0);
		assertNotNull(cmd.getOutputs());
		assertTrue(cmd.getOutputs().size() > 0);
	}

	@Test
	public void shouldFailOnInvalidCommand() {
		Command cmd = new Command("invalid_command", null, "/");

		cmd.execute();

		assertTrue(cmd.getExitStatus() == Command.COMMAND_FAILED);
		assertTrue(cmd.wasStarted());
		assertTrue(cmd.isCompleted());
		assertNotNull(cmd.getException());

		assertNull(cmd.getErrorLines());
		assertNull(cmd.getErrors());
		assertNull(cmd.getOutputLines());
		assertNull(cmd.getOutputs());
	}

	@Test
	public void shouldFailOnInvalidArguments() {
		Command cmd = new Command(Arrays.asList(new String[] {COMMAND, "invalid_argument"}));

		cmd.execute();

		assertTrue(cmd.getExitStatus() != 0);
		assertTrue(cmd.wasStarted());
		assertTrue(cmd.isCompleted());
		assertNull(cmd.getException());
		assertNotNull(cmd.getErrorLines());
		assertTrue(cmd.getErrorLines().length > 0);
		assertNotNull(cmd.getErrors());
		assertTrue(cmd.getErrors().size() > 0);
		assertNotNull(cmd.getOutputLines());
		assertTrue(cmd.getOutputs().size() == 0);
	}
}
