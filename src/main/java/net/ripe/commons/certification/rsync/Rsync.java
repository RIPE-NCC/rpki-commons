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
