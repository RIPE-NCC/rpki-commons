package net.ripe.rpki.commons.crypto.cms.manifest;


/**
 * RuntimeException to wrap checked Exceptions. In general we have no
 * way to recover from any of the checked Exceptions related to Manifests
 * so we might as well throw a RuntimeException..
 */
public class ManifestCmsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ManifestCmsException(Exception e) {
        super(e);
    }

}
