package net.ripe.commons.provisioning.payload.list.response;

import java.util.List;

import net.ripe.commons.provisioning.payload.common.CertificateElement;
import net.ripe.commons.provisioning.payload.common.GenericClassElement;


/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2
 * 
 * This type of class element contains a current certificate element for each key pair,
 * as oposed to just one in the CertificateIssuanceResponse.
 */
public class ResourceClassListResponseClassElement extends GenericClassElement {
    
    public List<CertificateElement> getCertificateElements() {
        return certificateElements;
    }

    public GenericClassElement setCertificateElements(List<CertificateElement> resourceClasses) {
        this.certificateElements = resourceClasses;
        return this;
    }
}
