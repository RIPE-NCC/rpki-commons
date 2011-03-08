package net.ripe.commons.certification.x509cert;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static net.ripe.commons.certification.x509cert.AbstractX509CertificateWrapper.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import net.ripe.commons.certification.rfc3779.ResourceExtensionEncoder;
import net.ripe.commons.certification.rfc3779.ResourceExtensionParser;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

public abstract class X509CertificateParser<T extends AbstractX509CertificateWrapper> {

    private static final String[] ALLOWED_SIGNATURE_ALGORITHM_OIDS = {
        PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(),
        PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(),
        PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(),
    };

    private byte[] encoded;

    protected X509Certificate certificate;

    protected ValidationResult result;

	private final Class<T> certificateClass;

    protected X509CertificateParser(Class<T> certificateClass, ValidationResult result) {
        this.certificateClass = certificateClass;
		this.result = result;
    }

	public void parse(String location, byte[] encoded) { //NOPMD - ArrayIsStoredDirectly
        this.encoded = encoded;

        result.push(location);

        parse();
        if (!result.hasFailureForLocation(location)) {
            validateCertificatePolicy();
            validateSignatureAlgorithm();
	        validateResourceExtensions();
        }
    }

	public ValidationResult getValidationResult() {
        return result;
    }

    abstract public T getCertificate(); 
//    {
//        if (result.hasFailures()) {
//            throw new IllegalArgumentException("Certificate validation failed");
//        }
//        
//        if (isResourceExtensionPresent()) {
//        	return certificateClass.cast(new X509ResourceCertificate(certificate));
//        } else {
//        	return certificateClass.cast(new X509PlainCertificate(certificate));
//        }
//    }

    private void parse() {
        InputStream input = null;
        try {
            input = new ByteArrayInputStream(encoded);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) factory.generateCertificate(input);
        } catch (CertificateException e) {
            certificate = null;
        } finally {
            IOUtils.closeQuietly(input);
        }
        result.notNull(certificate, CERTIFICATE_PARSED);
    }

    private void validateCertificatePolicy() {
        if (!result.notNull(certificate.getCriticalExtensionOIDs(), CRITICAL_EXT_PRESENT)) {
            return;
        }

        result.isTrue(certificate.getCriticalExtensionOIDs().contains(X509Extensions.CertificatePolicies.getId()), POLICY_EXT_CRITICAL);

        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extensions.CertificatePolicies.getId());
            if (!result.notNull(extensionValue, POLICY_EXT_VALUE)) {
                return;
            }
            ASN1Sequence policies = ASN1Sequence.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue));
            if (!result.isTrue(policies.size() == 1, SINGLE_CERT_POLICY)) {
                return;
            }
            PolicyInformation policy = PolicyInformation.getInstance(policies.getObjectAt(0));
            result.isTrue(policy.getPolicyQualifiers() == null, POLICY_QUALIFIER);
            if (!result.notNull(policy.getPolicyIdentifier(), POLICY_ID_PRESENT)) {
                return;
            }
            result.isTrue(POLICY_OID.equals(policy.getPolicyIdentifier()), POLICY_ID_VERSION);
        } catch (IOException e) {
            result.isTrue(false, POLICY_VALIDATION);
        }
    }

    private void validateSignatureAlgorithm() {
        result.isTrue(ArrayUtils.contains(ALLOWED_SIGNATURE_ALGORITHM_OIDS, certificate.getSigAlgOID()), CERTIFICATE_SIGNATURE_ALGORITHM);
    }

	private void validateResourceExtensions() {
		if (isResourceExtensionPresent()) {
			result.isTrue(true, RESOURCE_EXT_PRESENT);
			result.isTrue(true, AS_OR_IP_RESOURCE_PRESENT);
			parseResourceExtensions();
		} else {
			result.isFalse(X509ResourceCertificate.class.isAssignableFrom(certificateClass), AS_OR_IP_RESOURCE_PRESENT);
		}
	}

    private boolean isResourceExtensionPresent() {
		if (certificate.getCriticalExtensionOIDs() == null) {
			return false;
		}

		return certificate.getCriticalExtensionOIDs().contains(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS)
	    	|| certificate.getCriticalExtensionOIDs().contains(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS);
	}

	private void parseResourceExtensions() {
	    ResourceExtensionParser parser = new ResourceExtensionParser();
	    boolean ipInherited = false;
	    boolean asInherited = false;
	    byte[] ipAddressBlocksExtension = certificate.getExtensionValue(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS);
	    if (ipAddressBlocksExtension != null) {
	        IpResourceSet ipResources = parser.parseIpAddressBlocks(ipAddressBlocksExtension);
	        if (ipResources == null) {
	            ipInherited = true;
	        }
	    }
	    byte[] asnExtension = certificate.getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS);
	    if (asnExtension != null) {
	        IpResourceSet asResources = parser.parseAsIdentifiers(asnExtension);
	        if (asResources == null) {
	            asInherited = true;
	        }
	    }
	    result.isTrue(ipInherited == asInherited, PARTIAL_INHERITANCE);
	}

//	public static X509CertificateParser<X509PlainCertificate> forPlainCertificate() {
//		return forPlainCertificate(new ValidationResult());
//	}
//
//	public static X509CertificateParser<X509PlainCertificate> forPlainCertificate(ValidationResult result) {
//	    return new X509CertificateParser<X509PlainCertificate>(X509PlainCertificate.class, result);
//	}

}
