package net.ripe.commons.certification.validation.objectvalidators;

import java.net.URI;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

/**
 * Represents the context used to validate an issued object. The context
 * contains the issuing certificate, its location, and the effective resource
 * set. The effective resource set must be used, in case the certificate
 * contains inherited IP resources.
 */
public class CertificateRepositoryObjectValidationContext {

	private final URI location;

	private final X509ResourceCertificate certificate;

	private final IpResourceSet resources;

    public CertificateRepositoryObjectValidationContext(URI location, X509ResourceCertificate certificate) {
    	this(location, certificate, certificate.getResources());
    }

	public CertificateRepositoryObjectValidationContext(URI location, X509ResourceCertificate certificate, IpResourceSet resources) {
		this.location = location;
		this.certificate = certificate;
		this.resources = resources;
	}

    public URI getLocation() {
		return location;
	}

	public X509ResourceCertificate getCertificate() {
		return certificate;
	}

	public IpResourceSet getResources() {
		return resources;
	}

	public URI getManifestURI() {
		return certificate.getManifestUri();
	}

	public URI getRepositoryURI() {
		return certificate.getRepositoryUri();
	}

	public CertificateRepositoryObjectValidationContext createChildContext(URI childLocation, X509ResourceCertificate childCertificate) {
		if (childCertificate.getResources() instanceof InheritedIpResourceSet) {
			return new CertificateRepositoryObjectValidationContext(childLocation, childCertificate, resources);
		} else {
			return new CertificateRepositoryObjectValidationContext(childLocation, childCertificate, childCertificate.getResources());
		}
	}

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(location).append(certificate).append(resources).toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final CertificateRepositoryObjectValidationContext that = (CertificateRepositoryObjectValidationContext) obj;
        return new EqualsBuilder()
                .append(this.getLocation(), that.getLocation())
                .append(this.getCertificate(), that.getCertificate())
                .append(this.getResources(), that.getResources())
                .isEquals();
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
    }
}
