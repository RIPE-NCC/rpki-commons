package net.ripe.commons.certification.cms;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;

import net.ripe.commons.certification.Asn1Util;
import net.ripe.commons.certification.x509cert.X509CertificateUtil;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.joda.time.DateTimeUtils;

public abstract class CmsObjectBuilder {

    protected byte[] generateCms(X509Certificate signingCertificate, PrivateKey privateKey, String signatureProvider, String contentTypeOid, ASN1Encodable encodableContent) {
        byte[] result;
        try {
            result = doGenerate(signingCertificate, privateKey, signatureProvider, contentTypeOid, encodableContent);
        } catch (NoSuchAlgorithmException e) {
            throw new CmsObjectBuilderException(e);
        } catch (NoSuchProviderException e) {
            throw new CmsObjectBuilderException(e);
        } catch (CMSException e) {
            throw new CmsObjectBuilderException(e);
        } catch (IOException e) {
            throw new CmsObjectBuilderException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CmsObjectBuilderException(e);
        } catch (CertStoreException e) {
            throw new CmsObjectBuilderException(e);
        }
        return result;
    }

    private byte[] doGenerate(X509Certificate signingCertificate, PrivateKey privateKey, String signatureProvider, String contentTypeOid, ASN1Encodable encodableContent) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertStoreException, CMSException, NoSuchProviderException, IOException {
        byte[] subjectKeyIdentifier = X509CertificateUtil.getSubjectKeyIdentifier(signingCertificate);
        Validate.notNull(subjectKeyIdentifier, "certificate must contain SubjectKeyIdentifier extension");

        CollectionCertStoreParameters certStoreParameters = new CollectionCertStoreParameters(Collections.singleton(signingCertificate));
        CertStore certStore = CertStore.getInstance("Collection", certStoreParameters);
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        AttributeTable signedAttributeTable = createSignedAttributes();
        generator.addSigner(privateKey, subjectKeyIdentifier, CmsObject.DIGEST_ALGORITHM_OID, signedAttributeTable, null);
        generator.addCertificatesAndCRLs(certStore);

        byte[] content = Asn1Util.encode(encodableContent);
        CMSSignedData data = generator.generate(contentTypeOid, new CMSProcessableByteArray(content), true, signatureProvider);
        return data.getEncoded();
    }

    private AttributeTable createSignedAttributes() {
        Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>(); //NOPMD - ReplaceHashtableWithMap
        Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date(DateTimeUtils.currentTimeMillis()))));
        attributes.put(CMSAttributes.signingTime, signingTimeAttribute);
        return new AttributeTable(attributes);
    }
}
