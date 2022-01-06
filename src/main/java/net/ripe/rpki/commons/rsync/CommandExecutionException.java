package net.ripe.rpki.commons.rsync;

public class CommandExecutionException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public CommandExecutionException(Throwable cause) {
        super(cause);
    }
}
