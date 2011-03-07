package net.ripe.commons.certification.cms;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.joda.time.DateTime;

/**
 * Helper class for the creation or ResourceCertificate using CMS objects. 
 */
public class CmsObjectInfo {
	
    private byte[] encoded;
    private X509ResourceCertificate resourceCertificate;
    private String contentType;
    private DateTime signingTime;
    
	public CmsObjectInfo(byte[] encoded, X509ResourceCertificate resourceCertificate, String contentType, DateTime signingTime) { //NOPMD - ArrayIsStoredDirectly
		this.encoded = encoded;
		this.resourceCertificate = resourceCertificate;
		this.contentType = contentType;
		this.signingTime = signingTime;
	}

	public byte[] getEncoded() {
		return encoded;
	}

	public X509ResourceCertificate getCertificate() {
		return resourceCertificate;
	}

	public String getContentType() {
		return contentType;
	}

	public DateTime getSigningTime() {
		return signingTime;
	}

}
