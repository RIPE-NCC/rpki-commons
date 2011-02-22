package net.ripe.commons.certification.validation.objectvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Arrays;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509PlainCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.joda.time.DateTime;

public class X509ResourceCertificateParentChildValidator implements X509ResourceCertificateValidator {

	private static final int KEYCERTSIGN_INDEX = 5; //http://www.ietf.org/rfc/rfc2459.txt
    private X509PlainCertificate parent;
	private X509PlainCertificate child;
	private X509Crl crl;
	private IpResourceSet resources;
	private ValidationResult result;


	public X509ResourceCertificateParentChildValidator(ValidationResult result, X509PlainCertificate parent, X509Crl crl, IpResourceSet resources) {
		this.result = result;
		this.parent = parent;
		this.crl = crl;
		this.resources = resources;
	}

	@Override
    public void validate(String location, X509PlainCertificate certificate) {
		this.child = certificate;
		result.push(location);

		verifySignature();
		verifyValidity();
		verifyCrl();
		verifyIssuer();
		verifyKeyUsage();
		verifyAuthorityKeyIdentifier();

		if ((parent instanceof X509ResourceCertificate) && (certificate instanceof X509ResourceCertificate)) {
			verifyResources();
		} else if ((parent instanceof X509ResourceCertificate) || (certificate instanceof X509ResourceCertificate)) {
			result.isTrue(false, DIFFERENT_CERTIFICATE_TYPES);
		}
	}

	@Override
    public ValidationResult getValidationResult() {
		return result;
	}


	private void verifySignature() {
		result.isTrue(parent.isCa(), ISSUER_IS_CA);

		boolean errorOccured = false;
		try {
			child.verify(parent.getPublicKey()); // signed with issuer's public key
		} catch (SignatureException e) {
			errorOccured = true;
		} catch (InvalidKeyException e) {
			errorOccured = true;
		}

		result.isFalse(errorOccured, SIGNATURE_VALID);
	}

	private void verifyCrl() {
		if (crl == null) {
			result.isTrue(child.isRoot(), CRL_REQUIRED);
			return;
		}

		boolean errorOccured = false;
		try {
			crl.verify(parent.getPublicKey());
		} catch (SignatureException e) {
			errorOccured = true;
		}

		result.isFalse(errorOccured, CRL_SIGNATURE_VALID);
		result.isFalse(crl.isRevoked(child.getCertificate()), CERT_REVOKED);
	}

	private void verifyValidity() {
    	DateTime now = new DateTime();

    	result.isFalse(
    		now.isBefore(
    			child.getValidityPeriod().getNotValidBefore()),
    			NOT_VALID_BEFORE,
    			child.getValidityPeriod().getNotValidBefore()
    	);
    	result.isFalse(
    		now.isAfter(
    			child.getValidityPeriod().getNotValidAfter()),
    			NOT_VALID_AFTER,
    			child.getValidityPeriod().getNotValidAfter()
    	);
	}

	private void verifyIssuer() {
		result.isTrue(parent.getSubject().equals(child.getIssuer()), PREV_SUBJECT_EQ_ISSUER);
	}

	private void verifyKeyUsage() {
    	if (child.isCa()) {
    		boolean[] keyUsage = child.getCertificate().getKeyUsage();
    		if (!result.notNull(keyUsage, KEY_USAGE_EXT_PRESENT)) {
    			return;
    		}
    		result.isTrue(keyUsage[KEYCERTSIGN_INDEX], KEY_CERT_SIGN);
    	}
	}

	private void verifyAuthorityKeyIdentifier() {
		if (child.isRoot()) {
			// self-signed cert does not have AKI
			return;
		}
		byte[] ski = parent.getSubjectKeyIdentifier();
		byte[] aki = child.getAuthorityKeyIdentifier();
		if ((!result.notNull(ski, SKI_PRESENT)) || (!result.notNull(aki, AKI_PRESENT))) {
			return;
		}
		result.isTrue(Arrays.equals(ski, aki), PREV_SKI_EQ_AKI);
	}

	private void verifyResources() {
		IpResourceSet childResourceSet = ((X509ResourceCertificate)child).getResources();

		if (child.isRoot()) {
			// root certificate cannot have inherited resources
			result.isFalse(childResourceSet instanceof InheritedIpResourceSet, RESOURCE_RANGE);
		} else if (childResourceSet instanceof InheritedIpResourceSet) {
			// for other certs inherited resources should always be okay
			return;
		} else {
			// otherwise the child resources cannot exceed the specified resources
			result.isTrue(resources.contains(childResourceSet), RESOURCE_RANGE);
		}
	}



}
