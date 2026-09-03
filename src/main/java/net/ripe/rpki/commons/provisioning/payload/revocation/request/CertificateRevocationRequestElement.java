package net.ripe.rpki.commons.provisioning.payload.revocation.request;

import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * See <a href="https://datatracker.ietf.org/doc/html/rfc6492#section-3.5.1">https://datatracker.ietf.org/doc/html/rfc6492#section-3.5.1</a>
 */
public class CertificateRevocationRequestElement {
    private String className;
    private String subjectPublicKey;

    public String getClassName() {
        return className;
    }

    CertificateRevocationRequestElement setClassName(String className) {
        this.className = className;
        return this;
    }

    public String getSubjectPublicKey() {
        return subjectPublicKey;
    }

    public CertificateRevocationRequestElement setSubjectPublicKey(String subjectPublicKey) {
        this.subjectPublicKey = subjectPublicKey;
        return this;
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this);
    }

}
