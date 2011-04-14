package net.ripe.commons.provisioning.payload.issue.response;

import java.util.Arrays;

import net.ripe.commons.provisioning.payload.common.CertificateElement;
import net.ripe.commons.provisioning.payload.common.GenericClassElement;

/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.2
 * <p/>
 * This type of class element contains the signed certificate for this request/response
 * as oposed to all current certificate elements as used in the list response.
 */
public class CertificateIssuanceResponseClassElement extends GenericClassElement {

    public void setCertificateElement(CertificateElement certificateElement) {
        setCertificateElements(Arrays.asList(certificateElement));
    }

    public CertificateElement getCertificateElement() {
        if (getCertificateElements().size() == 1) {
            return getCertificateElements().get(0);
        }
        return null;
    }

}
