/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.rsync;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

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
        Command cmd = new Command(Arrays.asList(new String[]{COMMAND, "invalid_argument"}));

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
