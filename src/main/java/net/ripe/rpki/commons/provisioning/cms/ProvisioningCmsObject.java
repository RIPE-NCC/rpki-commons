package net.ripe.rpki.commons.provisioning.cms;

import com.google.common.base.Preconditions;
import lombok.NonNull;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import org.joda.time.DateTime;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;


public class ProvisioningCmsObject {

    private byte[] encodedContent;
    private final X509Certificate cmsCertificate;
    private final Collection<X509Certificate> caCertificates;
    private final X509CRL crl;
    private AbstractProvisioningPayload payload;
    /** Signing time MUST be present https://datatracker.ietf.org/doc/html/rfc6492#section-3.1.1.6.4.3 */
    private final DateTime signingTime;

    public ProvisioningCmsObject(byte[] encodedContent, X509Certificate cmsCertificate, Collection<X509Certificate> caCertificates, X509CRL crl, AbstractProvisioningPayload payload, @NonNull DateTime signingTime) {
        // -
        // ArrayIsStoredDirectly
        this.encodedContent = encodedContent;
        this.cmsCertificate = cmsCertificate;
        this.caCertificates = caCertificates;
        this.crl = crl;
        this.payload = payload;
        this.signingTime = signingTime;
    }

    public byte[] getEncoded() {
        return encodedContent;
    }

    public X509Certificate getCmsCertificate() {
        return cmsCertificate;
    }

    public AbstractProvisioningPayload getPayload() {
        return payload;
    }

    /**
     * <p>
     * ProvisioningCMSObjects may optionally contain a number of CA certificates.
     * As far as we know, no implementation is using this though. It is provided here
     * for completeness but in all likelihood not needed.
     * </p>
     * Note: the validator expects to be given the direct (trusted) parent CA certificate
     * to the EE certificate used to sign the CMS.
     */
    public Collection<X509Certificate> getCaCertificates() {
        return caCertificates;
    }

    public X509CRL getCrl() {
        return crl;
    }

    /**
     * This is used to check against replay attacks, see <a
     * href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.2"
     * >http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.2</a><br >
     */
    public DateTime getSigningTime() {
        return signingTime;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encodedContent);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ProvisioningCmsObject other = (ProvisioningCmsObject) obj;
        return Arrays.equals(encodedContent, other.getEncoded());
    }

}
