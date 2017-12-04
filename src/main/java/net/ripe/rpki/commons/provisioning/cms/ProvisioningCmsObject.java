/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.provisioning.cms;

import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.joda.time.DateTime;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;


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
            Collection<SignerInformation> signers = sis.getSigners();
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
