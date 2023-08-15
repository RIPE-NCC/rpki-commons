package net.ripe.rpki.commons.crypto.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import static net.ripe.rpki.commons.crypto.cms.CMSUtils.attachSignersToOutputStream;
import static net.ripe.rpki.commons.crypto.cms.CMSUtils.createDerSetFromList;
import static net.ripe.rpki.commons.crypto.cms.CMSUtils.fixAlgID;
import static net.ripe.rpki.commons.crypto.cms.CMSUtils.getNullSafeOutputStream;

/**
 * CMSSignedDataGenerator from BouncyCastle was originally for PKCS7, which follows RFC5652, allowing BER signed data.
 *
 * This RPKISignedDataGenerator is doing the same, except that following RFC6488, it generates DER encoding of the
 * CMSSignedData.
 *
 */
public class RPKISignedDataGenerator extends CMSSignedDataGenerator
{
    public RPKISignedDataGenerator() {
    }

    /**
     * Generate a CMS Signed Data object which can be carrying a detached CMS signature, or have encapsulated data,
     * depending on the value of the encapsulated parameter.
     *
     * @param content the content to be signed.
     * @param encapsulate true if the content should be encapsulated in the signature, false otherwise.
     */
    @Override
    public CMSSignedData generate(
        // FIXME Avoid accessing more than once to support CMSProcessableInputStream
        CMSTypedData content,
        boolean encapsulate)
        throws CMSException
    {
        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        ASN1EncodableVector  signerInfos = new ASN1EncodableVector();

        digests.clear();  // clear the current preserved digest state

        //
        // add the precalculated SignerInfo objects.
        //
        for (Object o : _signers) {
            SignerInformation signer = (SignerInformation) o;
            digestAlgs.add(fixAlgID(signer.getDigestAlgorithmID()));

            if(!signer.getContentType().equals(content.getContentType())){
                throw new IllegalArgumentException("Precalculated signer info must match content type");
            }
            signerInfos.add(signer.toASN1Structure());
        }

        //
        // add the SignerInfo objects
        //
        ASN1ObjectIdentifier contentTypeOID = content.getContentType();

        ASN1OctetString octs = null;

        if (content.getContent() != null)
        {
            ByteArrayOutputStream bOut = null;

            if (encapsulate)
            {
                bOut = new ByteArrayOutputStream();
            }

            OutputStream cOut = attachSignersToOutputStream(signerGens, bOut);

            // Just in case it's unencapsulated and there are no signers!
            cOut = getNullSafeOutputStream(cOut);

            try
            {
                content.write(cOut);

                cOut.close();
            }
            catch (IOException e)
            {
                throw new CMSException("data processing exception: " + e.getMessage(), e);
            }

            if (encapsulate)
            {
                octs = new DEROctetString(bOut.toByteArray());
            }
        }

        for (Object signerGen : signerGens) {
            SignerInfoGenerator sGen = (SignerInfoGenerator) signerGen;
            SignerInfo inf = sGen.generate(contentTypeOID);

            digestAlgs.add(inf.getDigestAlgorithm());
            signerInfos.add(inf);

            byte[] calcDigest = sGen.getCalculatedDigest();

            if (calcDigest != null) {
                digests.put(inf.getDigestAlgorithm().getAlgorithm().getId(), calcDigest);
            }
        }

        ASN1Set certificates = null;

        if (!certs.isEmpty())
        {
            certificates = createDerSetFromList(certs);
        }

        ASN1Set certrevlist = null;

        if (!crls.isEmpty())
        {
            certrevlist = createDerSetFromList(crls);
        }

        ContentInfo encInfo = new ContentInfo(contentTypeOID, octs);

        RPKISignedData sd = new RPKISignedData(
                new DERSet(digestAlgs),
                encInfo,
                certificates,
                certrevlist,
                new DERSet(signerInfos));

        RPKIContentInfo contentInfo = new RPKIContentInfo(CMSObjectIdentifiers.signedData, sd);

        return new CMSSignedData(content, contentInfo);
    }

}

