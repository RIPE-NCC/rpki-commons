package net.ripe.rpki.commons.xml;

public class DomXmlSerializerException extends RuntimeException {
    public DomXmlSerializerException(Exception e) {
        super(e);
    }

    public DomXmlSerializerException(final String message) {
        super(message);
    }

    public DomXmlSerializerException(final String message, final Exception e) {
        super(message, e);
    }
}
