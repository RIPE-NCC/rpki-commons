package net.ripe.commons.provisioning.cms;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;

import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;

import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.joda.time.DateTime;


public class ProvisioningCmsObject {

    private byte[] encodedContent;
    private final X509Certificate cmsCertificate;
    private final Collection<X509Certificate> caCertificates;
    private final X509CRL crl;
    private AbstractProvisioningPayload payload;

    public ProvisioningCmsObject(byte[] encodedContent, X509Certificate cmsCertificate, Collection<X509Certificate> caCertificates, X509CRL crl, AbstractProvisioningPayload payload) { // NOPMD
                                                                                                                                                   // -
                                                                                                                                                   // ArrayIsStoredDirectly
        this.encodedContent = encodedContent;
        this.cmsCertificate = cmsCertificate;
        this.caCertificates = caCertificates;
        this.crl = crl;
        this.payload = payload;
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
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(encodedContent);
            SignerInformationStore sis = cmsSignedData.getSignerInfos();

            @SuppressWarnings("unchecked")
            Collection<SignerInformation> signers = (Collection<SignerInformation>) sis.getSigners();
            for (SignerInformation signerInformation : signers) {
                AttributeTable signedAttributes = signerInformation.getSignedAttributes();
                Attribute signingTime = signedAttributes.get(CMSAttributes.signingTime);
                
                @SuppressWarnings("unchecked")
                Enumeration<Object> en = signingTime.getAttrValues().getObjects();
                while (en.hasMoreElements()) {
                    Object obj = en.nextElement();
                    if (obj instanceof DERUTCTime) {
                        DERUTCTime derTime = (DERUTCTime) obj;
                        return new DateTime(derTime.getDate());
                    }
                }
            }
            throw new IllegalArgumentException("Malformed encoded cms content");
        } catch (CMSException e) {
            throw new IllegalArgumentException("Malformed encoded cms content", e);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Malformed encoded cms content", e);
        }
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
