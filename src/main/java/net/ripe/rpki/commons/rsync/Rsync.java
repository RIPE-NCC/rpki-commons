package net.ripe.rpki.commons.rsync;

import lombok.Setter;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.*;

public class Rsync {

    private static final int DEFAULT_TIMEOUT_IN_SECONDS = 300;

    private static final String RSYNC_PROXY = "RSYNC_PROXY";

    private static final String RSYNC_COMMAND = "rsync";

    private static final Logger log = LoggerFactory.getLogger(Rsync.class);

    @Setter
    private @NotNull Clock clock = Clock.systemUTC();

    private Command command;

    private String source;

    private String destination;

    private final List<String> options = new ArrayList<>();

    private int timeoutInSeconds = DEFAULT_TIMEOUT_IN_SECONDS;

    private long startedAt;

    private long finishedAt;

    private String proxy;

    public Rsync() {
    }

    public Rsync(String source, String destination) {
        this.source = source;
        this.destination = destination;
    }

    /**
     * @param timeoutInSeconds the rsync(1) communication timeout in seconds.
     */
    public void setTimeoutInSeconds(int timeoutInSeconds) {
        if (timeoutInSeconds < 0) {
            throw new IllegalArgumentException("timeout must be non-negative");
        }
        this.timeoutInSeconds = timeoutInSeconds;
    }

    public void addOptions(String... options) {
        for (String option : options) {
            if (option != null) {
                this.options.add(option);
            }
        }
    }

    public void addOptions(Collection<String> options) {
        for (String option : options) {
            if (option != null) {
                this.options.add(option);
            }
        }
    }

    public boolean containsOption(String option) {
        return options.contains(option);
    }

    public void reset() {
        command = null;
        options.clear();
        source = null;
        destination = null;
        startedAt = 0;
        finishedAt = 0;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public void setProxy(String proxy) {
        this.proxy = proxy;
    }

    public String[] getErrorLines() {
        return command == null ? null : command.getErrorLines();
    }

    public String[] getOutputLines() {
        return command == null ? null : command.getOutputLines();
    }

    public boolean isCompleted() {
        return command != null && command.isCompleted();
    }

    public int getExitStatus() {
        return command == null ? -1 : command.getExitStatus();
    }

    public Exception getException() {
        return command == null ? null : command.getException();
    }

    public int execute() {
        List<String> args = new ArrayList<>();
        args.add(RSYNC_COMMAND);
        args.add("--timeout=" + timeoutInSeconds);
        args.addAll(options);
        if ((source != null) && (destination != null)) {
            args.add(source);
            args.add(destination);
        }

        final Command rsync;
        if (proxy != null) {
            Map<String, String> environment = System.getenv();
            if (System.getenv(RSYNC_PROXY) == null) {
                environment = new HashMap<>(environment);
                environment.put(RSYNC_PROXY, proxy);
            }
            rsync = new Command(args, environment);
        } else {
            rsync = new Command(args);
        }

        startedAt = clock.millis();
        try {
            rsync.execute();
            command = rsync;
            int exitStatus = rsync.getExitStatus();
            if (exitStatus != 0) {
                log.error("rsync command line: {}", args);
                log.error("rsync exit status: {}", exitStatus);
                log.error("rsync stderr: {}", rsync.getErrors());
                log.error("rsync stdout: {}", rsync.getOutputs());
            }

            return exitStatus;
        } finally {
            finishedAt = clock.millis();
        }
    }

    public long elapsedTime() {
        return finishedAt - startedAt;
    }
}
