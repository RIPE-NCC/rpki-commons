package net.ripe.rpki.commons.rsync;

public class RemoteCertificateFetcherException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public RemoteCertificateFetcherException(String msg, Exception e) {
        super(msg, e);
    }
}
