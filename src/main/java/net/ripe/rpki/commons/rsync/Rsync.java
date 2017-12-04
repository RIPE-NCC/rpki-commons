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

import org.joda.time.DateTimeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class Rsync {

    public static final int DEFAULT_TIMEOUT_IN_SECONDS = 300;

    private static final String COMMAND = "rsync";

    private static final Logger LOGGER = LoggerFactory.getLogger(Rsync.class);

    private Command command;

    private String source;

    private String destination;

    private List<String> options = new ArrayList<String>();

    private int timeoutInSeconds = DEFAULT_TIMEOUT_IN_SECONDS;

    private long startedAt;

    private long finishedAt;

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
        List<String> args = new ArrayList<String>();
        args.add(COMMAND);
        args.add("--timeout=" + timeoutInSeconds);
        args.addAll(options);
        if ((source != null) && (destination != null)) {
            args.add(source);
            args.add(destination);
        }

        Command rsync = new Command(args);
        startedAt = DateTimeUtils.currentTimeMillis();
        try {
            rsync.execute();
            command = rsync;
            int exitStatus = rsync.getExitStatus();
            if (exitStatus != 0) {
                LOGGER.error("rsync command line: " + args);
                LOGGER.error("rsync exit status: " + exitStatus);
                LOGGER.error("rsync stderr: " + rsync.getErrors());
                LOGGER.error("rsync stdout: " + rsync.getOutputs());
            }

            return exitStatus;
        } finally {
            finishedAt = DateTimeUtils.currentTimeMillis();
        }
    }

    public long elapsedTime() {
        return finishedAt - startedAt;
    }
}
