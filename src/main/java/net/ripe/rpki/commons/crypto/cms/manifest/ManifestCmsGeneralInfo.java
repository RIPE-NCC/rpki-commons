package net.ripe.rpki.commons.crypto.cms.manifest;

import org.joda.time.DateTime;

import java.io.Serializable;
import java.math.BigInteger;

public class ManifestCmsGeneralInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    private int version;
    private BigInteger number;
    private DateTime thisUpdateTime;
    private DateTime nextUpdateTime;
    private String fileHashAlgorithm;

    public ManifestCmsGeneralInfo(int version, BigInteger number, DateTime thisUpdateTime, DateTime nextUpdateTime, String fileHashAlgorithm) {
        this.version = version;
        this.number = number;
        this.thisUpdateTime = thisUpdateTime;
        this.nextUpdateTime = nextUpdateTime;
        this.fileHashAlgorithm = fileHashAlgorithm;
    }

    public int getVersion() {
        return version;
    }

    public BigInteger getNumber() {
        return number;
    }

    public DateTime getThisUpdateTime() {
        return thisUpdateTime;
    }

    public DateTime getNextUpdateTime() {
        return nextUpdateTime;
    }

    public String getFileHashAlgorithm() {
        return fileHashAlgorithm;
    }

}
