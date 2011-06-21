package net.ripe.commons.provisioning.payload.common;

import java.net.URI;
import java.util.List;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.provisioning.payload.issue.response.CertificateIssuanceResponseClassElement;
import net.ripe.commons.provisioning.payload.list.response.ResourceClassListResponseClassElement;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class GenericClassElementBuilder {

    private String className;
    private List<URI> certificateAuthorityUri;
    private IpResourceSet ipResourceSet;
    private DateTime validityNotAfter;
    private String siaHeadUri;
    private List<CertificateElement> certificateElements;
    private X509ResourceCertificate issuer;

    public GenericClassElementBuilder withValidityNotAfter(DateTime notAfter) {
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
        Validate.isTrue(validityNotAfter.getZone().equals(DateTimeZone.UTC), "Validity time must be in UTC timezone");
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
