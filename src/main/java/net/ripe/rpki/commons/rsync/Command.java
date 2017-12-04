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

import java.io.File;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;


public class Command extends Thread {

    public static final int NOT_EXECUTED = -1;
    public static final int COMMAND_FAILED = -2;

    private List<String> args;
    private Map<String, String> envp;
    private String execDir;

    private int exitStatus = NOT_EXECUTED;

    private boolean started;

    private Exception exception;

    private List<String> outputLines;
    private List<String> errorLines;


    public Command(String command) {
        this(command, null, null);
    }

    public Command(String command, Map<String, String> envp) {
        this(command, envp, null);
    }

    public Command(String command, Map<String, String> envp, String execdir) {
        this(Arrays.asList(command), envp, execdir);
    }

    public Command(List<String> args) {
        this(args, null, null);
    }

    public Command(List<String> args, Map<String, String> envp) {
        this(args, envp, null);
    }

    public Command(List<String> args, Map<String, String> envp, String execdir) {
        this.args = args;
        this.envp = envp;
        this.execDir = execdir;
    }

    public void execute() {
        started = true;
        try {
            exitStatus = runExternalCommand();
        } catch (CommandExecutionException e) {
            exitStatus = COMMAND_FAILED;
        }
    }

    private int runExternalCommand() {
        try {
            File workDir = (execDir == null) ? null : new File(execDir);
            ProcessBuilder pb = new ProcessBuilder(args);
            pb.directory(workDir);
            if (envp != null) {
                pb.environment().putAll(envp);
            }
            Process process = pb.start();

            /* Deadlock is possible if the subprocess generates enough output to overflow the system.
             * A robust solution requires draining the process stdout and stderr in separate threads. */
            InputStream processErrorStream = process.getErrorStream();
            InputStream processOutputSteam = process.getInputStream();

            ProcessReader errorReader = new ProcessReader(processErrorStream);
            errorReader.start();

            ProcessReader outputReader = new ProcessReader(processOutputSteam);
            outputReader.start();

            //allows the readers to start
            yield();

            outputReader.join();
            errorReader.join();

            outputLines = outputReader.getLines();
            errorLines = errorReader.getLines();

            return process.waitFor();
        } catch (Exception e) {
            exception = e;
            throw new CommandExecutionException(e);
        }
    }

    public boolean isCompleted() {
        return exitStatus != NOT_EXECUTED;
    }

    public boolean wasStarted() {
        return started;
    }

    public int getExitStatus() {
        return exitStatus;
    }

    public String[] getOutputLines() {
        return outputLines == null ? null : outputLines.toArray(new String[outputLines.size()]);
    }

    public List<String> getOutputs() {
        return outputLines;
    }

    public String[] getErrorLines() {
        return errorLines == null ? null : errorLines.toArray(new String[errorLines.size()]);
    }

    public List<String> getErrors() {
        return errorLines;
    }

    public Exception getException() {
        return exception;
    }
}
