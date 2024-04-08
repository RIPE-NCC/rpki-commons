package net.ripe.rpki.commons.provisioning.payload.list.response;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.provisioning.payload.common.CertificateElement;
import net.ripe.rpki.commons.provisioning.payload.common.GenericClassElement;


/**
 * See: http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.2
 *
 * This type of class element contains a current certificate element for each key pair,
 * as opposed to just one in the CertificateIssuanceResponse.
 */
public class ResourceClassListResponseClassElement extends GenericClassElement {
    public boolean containsResourceCertificate(X509ResourceCertificate resourceCertificate) {
        if (getCertificateElements() == null) {
            return false;
        }
        for (CertificateElement element : getCertificateElements()) {
            if (resourceCertificate.equals(element.getCertificate())) {
                return true;
            }
        }
        return false;
    }
}
