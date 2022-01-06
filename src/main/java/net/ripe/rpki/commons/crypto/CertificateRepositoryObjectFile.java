package net.ripe.rpki.commons.crypto;

import org.apache.commons.lang3.Validate;

public class CertificateRepositoryObjectFile<T extends CertificateRepositoryObject> {

    private final Class<T> expectedType;

    private final String name;

    private final byte[] content;


    public CertificateRepositoryObjectFile(Class<T> expectedType, String name, byte[] content) { //NOPMD - ArrayIsStoredDirectly
        Validate.notNull(expectedType);
        Validate.notNull(name);
        Validate.notNull(content);
        this.expectedType = expectedType;
        this.name = name;
        this.content = content;
    }

    public Class<T> getExpectedType() {
        return expectedType;
    }

    public String getName() {
        return name;
    }

    public byte[] getContent() {
        return content;
    }
}
