package net.ripe.rpki.commons.validation.objectvalidators;

import com.google.common.collect.Lists;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateObject;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509RouterCertificate;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.net.URI;
import java.util.List;

/**
 * Represents the context used to validate an issued object. The context
 * contains the issuing certificate, its location, and the effective resource
 * set. The effective resource set must be used, in case the certificate
 * contains inherited IP resources.
 */
public class CertificateRepositoryObjectValidationContext {

    private final List<String> subjectChain;

    private final URI location;

    private final X509CertificateObject certificate;

    private final IpResourceSet resources;

    private IpResourceSet overclaiming = new IpResourceSet();

    public CertificateRepositoryObjectValidationContext(URI location, X509ResourceCertificate certificate) {
        this(location, certificate, certificate.getResources(), Lists.newArrayList(certificate.getSubject().getName()));
    }

    public CertificateRepositoryObjectValidationContext(URI location, X509ResourceCertificate certificate, IpResourceSet resources, List<String> subjectChain) {
        this.location = location;
        this.certificate = certificate;
        this.resources = resources;
        this.subjectChain = subjectChain;
    }

    public URI getLocation() {
        return location;
    }

    public X509ResourceCertificate getCertificate() {
        if (certificate instanceof X509ResourceCertificate) {
            return (X509ResourceCertificate) certificate;
        }
        throw new IllegalStateException("The certificate in the context is not of the type " + X509ResourceCertificate.class);
    }

    public X509RouterCertificate getRouterCertificate() {
        if (certificate instanceof X509RouterCertificate) {
            return (X509RouterCertificate) certificate;
        }
        throw new IllegalStateException("The certificate in the context is not of the type " + X509RouterCertificate.class);
    }

    public X509CertificateObject getUntypedCertificate() {
        return certificate;
    }

    public List<String> getSubjectChain() {
        return subjectChain;
    }

    public URI getManifestURI() {
        return getCertificate().getManifestUri();
    }

    public URI getRepositoryURI() {
        return getCertificate().getRepositoryUri();
    }

    public URI getRpkiNotifyURI() {
        return getCertificate().getRrdpNotifyUri();
    }

    public byte[] getSubjectKeyIdentifier() {
        return getCertificate().getSubjectKeyIdentifier();
    }

    public void addOverclaiming(IpResourceSet overclaiming) {
        this.overclaiming.addAll(overclaiming);
    }

    public CertificateRepositoryObjectValidationContext createChildContext(URI childLocation, X509ResourceCertificate childCertificate) {
        IpResourceSet effectiveResources = childCertificate.deriveResources(resources);
        removeOverclaimingResources(effectiveResources);
        List<String> childSubjects = Lists.newArrayList(subjectChain);
        childSubjects.add(childCertificate.getSubject().getName());
        return new CertificateRepositoryObjectValidationContext(childLocation, childCertificate, effectiveResources, childSubjects);
    }

    public IpResourceSet getResources() {
        IpResourceSet result = new IpResourceSet(resources);
        removeOverclaimingResources(result);
        return result;
    }

    private void removeOverclaimingResources(IpResourceSet resources) {
        if (overclaiming.isEmpty() || resources.isEmpty()) {
            return;
        }
        resources.removeAll(overclaiming);
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(location).append(certificate).append(resources).append(overclaiming).toHashCode();
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
                .append(this.resources, that.resources)
                .append(this.overclaiming, that.overclaiming)
                .isEquals();
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
    }
}
