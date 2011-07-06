package net.ripe.commons.certification.util;

import java.io.Serializable;
import java.util.StringTokenizer;

import org.apache.commons.lang.Validate;

/**
 * A versioned identifier to uniquely identify a specific version of an entity.
 * This is used to implement optimistic locking.
 */
public class VersionedId implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final long INITIAL_VERSION = -1;

    private final long id;

    private final long version;

    /**
     * Creates a versioned identifier with the initial version. Used when first
     * creating an entity with a predefined id.
     */
    public VersionedId(long id) {
        this(id, INITIAL_VERSION);
    }

    public VersionedId(long id, long version) {
        this.id = id;
        this.version = version;
    }

    public long getId() {
        return id;
    }

    public long getVersion() {
        return version;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + (int) (version ^ (version >>> 32));
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        final VersionedId other = (VersionedId) obj;
        if (id != other.id)
            return false;
        if (version != other.version)
            return false;
        return true;
    }

    @Override
    public String toString() {
        return id + ":" + version;
    }

    public static VersionedId parse(String s) {
        Validate.notNull(s, "string required");
        StringTokenizer tokenizer = new StringTokenizer(s, ":");
        int count = tokenizer.countTokens();
        Validate.isTrue(count == 1 || count == 2, "invalid number of tokens in versioned id");
        long id = Long.parseLong(tokenizer.nextToken());
        long version;
        if (tokenizer.hasMoreTokens()) {
            version = Long.parseLong(tokenizer.nextToken());
        } else {
            version = 0;
        }
        return new VersionedId(id, version);
    }

}
