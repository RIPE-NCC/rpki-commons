package net.ripe.commons.provisioning.payload.list.response;

import java.util.List;

import net.ripe.commons.provisioning.payload.common.CertificateElement;
import net.ripe.commons.provisioning.payload.common.GenericClassElement;


/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2
 * <p/>
 * This type of class element contains a current certificate element for each key pair,
 * as oposed to just one in the CertificateIssuanceResponse.
 */
public class ResourceClassListResponseClassElement extends GenericClassElement {

    // only reason for overriding is the different access modifier
    @Override
    public List<CertificateElement> getCertificateElements() {
        return super.getCertificateElements();
    }

    // only reason for overriding is the different access modifier
    @Override
    public void setCertificateElements(List<CertificateElement> resourceClasses) {
        super.setCertificateElements(resourceClasses);
    }
}
