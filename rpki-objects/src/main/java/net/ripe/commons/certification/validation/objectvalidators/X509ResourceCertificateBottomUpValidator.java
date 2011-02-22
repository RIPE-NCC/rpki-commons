package net.ripe.commons.certification.validation.objectvalidators;

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import net.ripe.commons.certification.CertificateRepositoryObjectFile;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509CertificateParser;
import net.ripe.commons.certification.x509cert.X509PlainCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;


public class X509ResourceCertificateBottomUpValidator implements X509ResourceCertificateValidator {

    private static final int MAX_CHAIN_LENGTH = 30;
    private X509ResourceCertificate certificate;
    private Collection<X509ResourceCertificate> trustAnchors;
    private ResourceCertificateLocator locator;
    private List<CertificateWithLocation> certificates = new LinkedList<CertificateWithLocation>();
    private ValidationResult result;
    private String location;


    public X509ResourceCertificateBottomUpValidator(ResourceCertificateLocator locator, X509ResourceCertificate... trustAnchors) {
        this(locator, Arrays.asList(trustAnchors));
    }

    public X509ResourceCertificateBottomUpValidator(ResourceCertificateLocator locator, Collection<X509ResourceCertificate> trustAnchors) {
        this(new ValidationResult(), locator, trustAnchors);
    }

    public X509ResourceCertificateBottomUpValidator(ValidationResult result, ResourceCertificateLocator locator, Collection<X509ResourceCertificate> trustAnchors) {
        this.result = result;
        this.location = "<unknown>";
        this.locator = locator;
        this.trustAnchors = trustAnchors;
    }

    @Override
    public ValidationResult getValidationResult() {
        return result;
    }

    @Override
    public void validate(String location, X509PlainCertificate certificate) {
        this.location = location;
        Validate.isTrue(certificate instanceof X509ResourceCertificate, "Only resource certificates can be validated");
    	this.certificate = (X509ResourceCertificate) certificate;

        buildCertificationList();
        if (result.hasFailures()) {
            // stop validation: certificate chain too long
            return;
        }

        checkTrustAnchor();

        X509ResourceCertificate parent = certificates.get(0).getCertificate();
        IpResourceSet resources = parent.getResources();
        for (CertificateWithLocation certificateWithLocation : certificates) {
        	String childLocation = certificateWithLocation.getLocation();
        	X509ResourceCertificate child = certificateWithLocation.getCertificate();

        	X509Crl crl = getCRL(child);

        	X509ResourceCertificateParentChildValidator validator = new X509ResourceCertificateParentChildValidator(result, parent, crl, resources);
        	validator.validate(childLocation, child);

        	IpResourceSet childResources = child.getResources();
        	if (! (childResources instanceof InheritedIpResourceSet) ) {
        		resources =  childResources;
        	}
        	parent = child;
        }
    }

    private void buildCertificationList() {
        certificates.add(0, new CertificateWithLocation(this.certificate, this.location));
        result.push(this.location);
        if (!result.isTrue(certificates.size() <= MAX_CHAIN_LENGTH, CERT_CHAIN_LENGTH, MAX_CHAIN_LENGTH)) {
            return;
        }

        X509ResourceCertificate cert = this.certificate;
        while (!cert.isRoot()) {
            CertificateRepositoryObjectFile<X509ResourceCertificate> parent = locator.findParent(cert);

            if (!result.notNull(parent, CERT_CHAIN_COMPLETE)) {
                return;
            }

            X509CertificateParser<X509ResourceCertificate> parser = X509CertificateParser.forResourceCertificate(result);
            parser.parse(parent.getName(), parent.getContent());
            if (result.hasFailures()) {
                return;
            }

            cert = parser.getCertificate();
            certificates.add(0, new CertificateWithLocation(cert, parent.getName()));
            result.push(parent.getName());
            if (!result.isTrue(certificates.size() <= MAX_CHAIN_LENGTH, CERT_CHAIN_LENGTH, MAX_CHAIN_LENGTH)) {
                return;
            }
        }

    }

    private X509Crl getCRL(X509ResourceCertificate certificate) {
    	CertificateRepositoryObjectFile<X509Crl> crlFile = locator.findCrl(certificate);
    	if (crlFile == null) {
    		return null;
    	}
    	return X509Crl.parseDerEncoded(crlFile.getContent());
    }

    private void checkTrustAnchor() {
    	if ((trustAnchors != null) && (trustAnchors.size() > 0)) {
    		result.isTrue(trustAnchors.contains(certificates.get(0).getCertificate()), ROOT_IS_TA);
    	}
    }

    private class CertificateWithLocation {

        private final X509ResourceCertificate certificate;
        private final String location;

        public CertificateWithLocation(X509ResourceCertificate certificate, String location) {
            super();
            this.location = location;
            this.certificate = certificate;
        }

        public X509ResourceCertificate getCertificate() {
            return certificate;
        }

        public String getLocation() {
            return location;
        }
    }
}
