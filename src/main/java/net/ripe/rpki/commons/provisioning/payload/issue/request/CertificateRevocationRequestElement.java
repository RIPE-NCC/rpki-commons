package net.ripe.rpki.commons.provisioning.payload.issue.request;


public class CertificateRevocationRequestElement {
    private final String className;
    private final String subjectPublicKey;

    public CertificateRevocationRequestElement(String className, String subjectPublicKey) {
        this.className = className;
        this.subjectPublicKey = subjectPublicKey;
    }

    public String getClassName() {
        return className;
    }

    public String getSubjectPublicKey() {
        return subjectPublicKey;
    }
}
