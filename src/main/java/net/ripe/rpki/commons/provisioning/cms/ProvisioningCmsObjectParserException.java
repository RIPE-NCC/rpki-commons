package net.ripe.rpki.commons.provisioning.cms;

public class ProvisioningCmsObjectParserException extends RuntimeException {

    private static final long serialVersionUID = 1L;


    public ProvisioningCmsObjectParserException(String message, Throwable cause) {
        super(message, cause);
    }

    public ProvisioningCmsObjectParserException(String message) {
        super(message);
    }
}
