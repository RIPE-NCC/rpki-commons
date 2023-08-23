package net.ripe.rpki.commons.provisioning.cms;

import lombok.Getter;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;


public class ProvisioningCmsObject {

    @Getter
    private final byte[] encodedContent;

    @Getter
    private final X509Certificate cmsCertificate;

    /**
     * <p>
     * ProvisioningCMSObjects may optionally contain a number of CA certificates.
     * As far as we know, no implementation is using this though. It is provided here
     * for completeness but in all likelihood not needed.
     * </p>
     * Note: the validator expects to be given the direct (trusted) parent CA certificate
     * to the EE certificate used to sign the CMS.
     */
    @Getter
    private final Collection<X509Certificate> caCertificates;
    @Getter
    private final X509CRL crl;
    @Getter
    private final AbstractProvisioningPayload payload;

    /** Signing time MUST be present {@see https://datatracker.ietf.org/doc/html/rfc6492#section-3.1.1.6.4.3}
     *
     * This is used to check against replay attacks, see <a
     * href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.2"
     * >http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.1.2</a><br >
     */
    @Getter
    private final @Nullable Instant signingTime;

    // No support for signingTime, which is a required attribute for valid objects.
    @Deprecated
    public ProvisioningCmsObject(byte[] encodedContent, X509Certificate cmsCertificate, Collection<X509Certificate> caCertificates, X509CRL crl, AbstractProvisioningPayload payload) {
        // -
        // ArrayIsStoredDirectly
        this.encodedContent = encodedContent;
        this.cmsCertificate = cmsCertificate;
        this.caCertificates = caCertificates;
        this.crl = crl;
        this.payload = payload;
        this.signingTime = null;
    }

    public ProvisioningCmsObject(byte[] encodedContent, X509Certificate cmsCertificate, Collection<X509Certificate> caCertificates, X509CRL crl, AbstractProvisioningPayload payload, @NotNull Instant signingTime) {
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
        return getEncodedContent();
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
