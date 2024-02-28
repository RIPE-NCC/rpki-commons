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
            Thread.yield();

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
