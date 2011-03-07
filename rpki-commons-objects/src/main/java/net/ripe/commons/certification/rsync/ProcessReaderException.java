package net.ripe.commons.certification.rsync;

public class ProcessReaderException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ProcessReaderException(Exception e) {
        super(e);
    }
}
