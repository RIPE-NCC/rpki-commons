package net.ripe.rpki.commons.provisioning.payload.common;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.provisioning.payload.issue.response.CertificateIssuanceResponseClassElement;
import net.ripe.rpki.commons.provisioning.payload.list.response.ResourceClassListResponseClassElement;
import org.apache.commons.lang3.Validate;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class GenericClassElementBuilder {

    private String className;
    private List<URI> certificateAuthorityUri = new ArrayList<>();
    private IpResourceSet ipResourceSet;
    private Instant validityNotAfter;
    private String siaHeadUri;
    private List<CertificateElement> certificateElements = new ArrayList<>();
    private X509ResourceCertificate issuer;

    public GenericClassElementBuilder withValidityNotAfter(Instant notAfter) {
        this.validityNotAfter = notAfter;
        return this;
    }

    public GenericClassElementBuilder withSiaHeadUri(String siaHead) {
        this.siaHeadUri = siaHead;
        return this;
    }

    public GenericClassElementBuilder withClassName(String className) {
        this.className = className;
        return this;
    }

    public GenericClassElementBuilder withIpResourceSet(IpResourceSet ipResourceSet) {
        this.ipResourceSet = ipResourceSet;
        return this;
    }


    public GenericClassElementBuilder withCertificateAuthorityUri(List<URI> caUri) {
        this.certificateAuthorityUri = caUri;
        return this;
    }

    public GenericClassElementBuilder withCertificateElements(List<CertificateElement> certificateElements) {
        this.certificateElements = certificateElements;
        return this;
    }

    public GenericClassElementBuilder withIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
        return this;
    }

    private void validateFields() {
        Validate.notNull(className, "No className provided");
        boolean rsyncUriFound = ResourceClassUtil.hasRsyncUri(certificateAuthorityUri);
        Validate.isTrue(rsyncUriFound, "No RSYNC URI provided");

        Validate.notNull(issuer, "issuer certificate is required");

        Validate.notNull(validityNotAfter, "Validity not after is required");
    }

    public ResourceClassListResponseClassElement buildResourceClassListResponseClassElement() {
        validateFields();
        ResourceClassListResponseClassElement classElement = new ResourceClassListResponseClassElement();
        setGenericClassElementFields(classElement);
        classElement.setCertificateElements(certificateElements);
        return classElement;
    }

    public CertificateIssuanceResponseClassElement buildCertificateIssuanceResponseClassElement() {
        validateFields();
        Validate.isTrue(certificateElements.size() == 1);
        CertificateIssuanceResponseClassElement classElement = new CertificateIssuanceResponseClassElement();
        setGenericClassElementFields(classElement);
        classElement.setCertificateElement(certificateElements.get(0));
        return classElement;
    }

    private void setGenericClassElementFields(GenericClassElement classElement) {
        classElement.setClassName(className);
        classElement.setCertUris(certificateAuthorityUri);
        classElement.setIpResourceSet(ipResourceSet);
        classElement.setIssuer(issuer);
        classElement.setValidityNotAfter(validityNotAfter);
        classElement.setSiaHeadUri(siaHeadUri);
    }

}
