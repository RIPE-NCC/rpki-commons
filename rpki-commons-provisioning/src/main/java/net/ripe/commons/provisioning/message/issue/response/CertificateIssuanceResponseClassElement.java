package net.ripe.commons.provisioning.message.issue.response;

import java.util.Arrays;

import net.ripe.commons.provisioning.message.common.CertificateElement;
import net.ripe.commons.provisioning.message.common.GenericClassElement;

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.2
 * 
 * This type of class element contains the signed certificate for this request/response
 * as oposed to all current certificate elements as used in the list response.
 */
public class CertificateIssuanceResponseClassElement extends GenericClassElement {

    public void setCertificateElement(CertificateElement certificateElement) {
        this.certificateElements = Arrays.asList(certificateElement);
    }
    
    public CertificateElement getCertificateElement() {
        if (certificateElements.size() == 1) {
            return certificateElements.get(0);
        }
        return null;
    }

}
