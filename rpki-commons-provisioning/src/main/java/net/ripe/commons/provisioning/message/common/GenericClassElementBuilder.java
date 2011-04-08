package net.ripe.commons.provisioning.message.common;

import java.util.Arrays;
import java.util.List;

import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.provisioning.message.issue.response.CertificateIssuanceResponseClassElement;
import net.ripe.commons.provisioning.message.list.response.ResourceClassListResponseClassElement;

import org.apache.commons.lang.Validate;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class GenericClassElementBuilder {

    private String className;
    private String[] certificateAuthorityUri;
    private String[] asn;
    private String[] ipv4ResourceSet;
    private String[] ipv6ResourceSet;
    private DateTime validityNotAfter;
    private String siaHeadUri;
    protected List<CertificateElement> certificateElements;
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

    public GenericClassElementBuilder withAllocatedAsn(String... asn) {
        this.asn = asn;
        return this;
    }

    public GenericClassElementBuilder withCertificateAuthorityUri(String... caUri) {
        this.certificateAuthorityUri = caUri;
        return this;
    }

    public GenericClassElementBuilder withIpv4ResourceSet(String... ipv4ResourceSet) {
        this.ipv4ResourceSet = ipv4ResourceSet;
        return this;
    }

    public GenericClassElementBuilder withIpv6ResourceSet(String... ipv6ResourceSet) {
        this.ipv6ResourceSet = ipv6ResourceSet;
        return this;
    }

    public GenericClassElementBuilder withCertificateElements(CertificateElement... certificateElements) {
        this.certificateElements = Arrays.asList(certificateElements);
        return this;
    }

    public GenericClassElementBuilder withIssuer(X509ResourceCertificate issuer) {
        this.issuer = issuer;
        return this;
    }

    private void validateFields() {
        Validate.notNull(className, "No className provided");
        Validate.isTrue(ResourceClassUtil.validateAsn(asn), "AS numbers should not start with AS");
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
        CertificateIssuanceResponseClassElement classElement = new CertificateIssuanceResponseClassElement();
        setGenericClassElementFields(classElement);
        classElement.setCertificateElement(certificateElements.get(0));
        return classElement;
    }

    private void setGenericClassElementFields(GenericClassElement classElement) {
        classElement.setClassName(className);
        classElement.setCertificateAuthorityUri(certificateAuthorityUri);
        classElement.setResourceSetAsNumbers(asn);
        classElement.setIpv4ResourceSet(ipv4ResourceSet);
        classElement.setIpv6ResourceSet(ipv6ResourceSet);
        classElement.setIssuer(issuer);
        classElement.setValidityNotAfter(validityNotAfter);
        classElement.setSiaHeadUri(siaHeadUri);
    }

    
}
