package net.ripe.commons.provisioning.message.common;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import org.apache.commons.lang.Validate;

import java.util.Arrays;
import java.util.List;

public abstract class ResourceClassCmsBuilder extends CommonCmsBuilder {

    private String className;
    private String[] certificateAuthorityUri;
    private String[] asn;
    private String[] ipv4ResourceSet;
    private String[] ipv6ResourceSet;
    private List<ResourceClass> resourceClasses;
    private X509ResourceCertificate issuer;

    public void withClassName(String className) {
        this.className = className;
    }

    public void withAllocatedAsn(String... asn) {
        this.asn = asn;
    }

    public void withCertificateAuthorityUri(String... caUri) {
        this.certificateAuthorityUri = caUri;
    }

    public void withIpv4ResourceSet(String... ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
    }

    public void withIpv6ResourceSet(String... ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
    }

    public void withResourceSet(ResourceClass... resourceClasses) {
        this.resourceClasses = Arrays.asList(resourceClasses);
    }

    public void withIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
    }

    @Override
    protected final void onValidateFields() {
        Validate.notNull(className, "No className provided");
        Validate.isTrue(ResourceClassUtil.validateAsn(asn), "AS numbers should not start with AS");
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(certificateAuthorityUri);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(issuer, "issuer certificate is required");

        onValidateAdditionalFields();
    }

    protected void onValidateAdditionalFields() {

    }

    protected final void setValuesInPayload(ResourceClassPayload resourceClassPayload) {
        resourceClassPayload.setClassName(className);
        resourceClassPayload.setCertificateAuthorityUri(certificateAuthorityUri);
        resourceClassPayload.setResourceSetAsNumbers(asn);
        resourceClassPayload.setIpv4ResourceSet(ipv4ResourceSet);
        resourceClassPayload.setIpv6ResourceSet(ipv6ResourceSet);
        resourceClassPayload.setResourceClasses(resourceClasses);
        resourceClassPayload.setIssuer(issuer);
    }
}
