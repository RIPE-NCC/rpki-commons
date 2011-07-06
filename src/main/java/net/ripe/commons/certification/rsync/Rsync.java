/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.rsync;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


public class Rsync {

	private static final String COMMAND = "rsync";

	private Command command;

	private String source;
	private String destination;
	private List<String> options = new ArrayList<String>();

	public Rsync() {
	}

	public Rsync(String source, String destination) {
		this.source = source;
		this.destination = destination;
	}

	public void addOptions(String... options) {
		for (int i = 0; i < options.length; i++) {
			if (options[i] != null) {
				this.options.add(options[i]);
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
		return command == null ? false : command.isCompleted();
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
		args.addAll(options);
		if ((source != null) && (destination != null)) {
			args.add(source);
			args.add(destination);
		}

		Command rsync = new Command(args);
		rsync.execute();
		command = rsync;
		return rsync.getExitStatus();
	}
}
