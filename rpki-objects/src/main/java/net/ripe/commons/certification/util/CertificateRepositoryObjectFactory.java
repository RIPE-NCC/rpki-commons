package net.ripe.commons.certification.util;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.x509cert.X509CertificateUtil;
import net.ripe.commons.certification.x509cert.X509PlainCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

public final class CertificateRepositoryObjectFactory {

    private CertificateRepositoryObjectFactory() {
        //Utility classes should not have a public or default constructor.
    }

    /**
     * @param encoded the DER encoded object.
     * @throws CertificateRepositoryObjectParserException when encoded object can't be parsed
     */
    public static CertificateRepositoryObject createCertificateRepositoryObject(byte[] encoded) {
        CertificateRepositoryObject result;

        // Try to parse as resource certificate
        result = tryParseAsX509ResourceCertificate(encoded);
        if (result != null) {
            return result;
        }

        // Try to parse as plain certificate
        result = tryParseAsX509PlainCertificate(encoded);
        if (result != null) {
        	return result;
        }

        // Try to parse as ROA
        result = tryParseAsROA(encoded);
        if (result != null) {
            return result;
        }

        // Try to parse as manifest
        result = tryParseAsManifest(encoded);
        if (result != null) {
            return result;
        }

        result = tryParseAsCrl(encoded);
        if (result != null) {
            return result;
        }

        throw new CertificateRepositoryObjectParserException("Could not parse encoded object");
    }


	private static CertificateRepositoryObject tryParseAsCrl(byte[] encoded) {
        try {
            return X509Crl.parseDerEncoded(encoded);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static X509ResourceCertificate tryParseAsX509ResourceCertificate(byte[] encoded) {
        try {
            return X509ResourceCertificate.parseDerEncoded(encoded);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static X509PlainCertificate tryParseAsX509PlainCertificate(byte[] encoded) {
    	try {
    		return X509CertificateUtil.parseDerEncoded(encoded);
    	} catch (IllegalArgumentException e) {
    		return null;
    	}
    }

    private static RoaCms tryParseAsROA(byte[] encoded) {
        try {
            return RoaCms.parseDerEncoded(encoded);
        } catch (IllegalArgumentException e){
            return null;
        }
    }

    private static ManifestCms tryParseAsManifest(byte[] encoded) {
        try {
            return ManifestCms.parseDerEncoded(encoded);
        } catch (IllegalArgumentException e) {
            return null;
        } catch (IllegalStateException e) {
            // Happens when we try to parse an RtaCMS as manifest; it contains a plain X509 EE Certificate, not a resource certificate.
            return null;
        }
    }
}
