package net.ripe.commons.certification.cms.manifest;

import java.io.Serializable;
import java.math.BigInteger;

import org.joda.time.DateTime;

public class ManifestCmsGeneralInfo implements Serializable {
	
    private static final long serialVersionUID = 1L;

    private int version;
	private BigInteger number;
	private DateTime thisUpdateTime;
    private DateTime nextUpdateTime;
    private String fileHashAlgorithm;

    public ManifestCmsGeneralInfo(int version, BigInteger number, DateTime thisUpdateTime, DateTime nextUpdateTime,	String fileHashAlgorithm) {
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
