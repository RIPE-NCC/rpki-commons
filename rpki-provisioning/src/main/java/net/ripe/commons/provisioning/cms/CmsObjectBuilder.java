package net.ripe.commons.provisioning.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.joda.time.DateTimeUtils;

public class CmsObjectBuilder {

    private X509Certificate certificate;

    private String signatureProvider;


    public CmsObjectBuilder withCertificate(X509Certificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public CmsObjectBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public CmsObject build(PrivateKey privateKey) {
        return new CmsObject(generateCms(certificate, privateKey, signatureProvider, encodableMessageContent()), certificate);
    }

    private byte[] generateCms(X509Certificate certificate, PrivateKey privateKey, String signatureProvider, ASN1Encodable encodableContent) {
        byte[] result;
        try {
            result = doGenerate(certificate, privateKey, signatureProvider, encodableContent);
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

    private byte[] doGenerate(X509Certificate certificate, PrivateKey privateKey, String signatureProvider, ASN1Encodable encodableContent) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertStoreException, CMSException, NoSuchProviderException, IOException {
        byte[] result;
        byte[] subjectKeyIdentifier = getSubjectKeyIdentifier(certificate);
        Validate.notNull(subjectKeyIdentifier, "certificate must contain SubjectKeyIdentifier extension");

        CollectionCertStoreParameters certStoreParameters = new CollectionCertStoreParameters(Collections.singleton(certificate));
        CertStore certStore = CertStore.getInstance("Collection", certStoreParameters);

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addCertificatesAndCRLs(certStore);

        AttributeTable signedAttributeTable = createSignedAttributes();
        generator.addSigner(privateKey, subjectKeyIdentifier, CmsObject.DIGEST_ALGORITHM_OID, signedAttributeTable, null);

        byte[] content = encode(encodableContent);
        CMSSignedData data = generator.generate(CmsObject.CONTENT_TYPE, new CMSProcessableByteArray(content), true, signatureProvider);
        result = data.getEncoded();
        return result;
    }

    private AttributeTable createSignedAttributes() {
        Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>(); //NOPMD - ReplaceHashtableWithMap
        Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date(DateTimeUtils.currentTimeMillis()))));
        attributes.put(CMSAttributes.signingTime, signingTimeAttribute);
        return new AttributeTable(attributes);
    }

    private ASN1Encodable encodableMessageContent() {
        return new DEROctetString(new byte[] {'f', 'o', 'o'}); // TODO:
    }

    private byte[] encode(ASN1Encodable value) { //FIXME: Asn1Util has a method like this
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DEROutputStream derOutputStream = new DEROutputStream(byteArrayOutputStream);
            derOutputStream.writeObject(value);
            derOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new CmsObjectBuilderException(e);
        }
    }

    private byte[] getSubjectKeyIdentifier(X509Extension certificate) { //FIXME: X509CertificateUtil has a method like this
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
            if (extensionValue == null) {
                return null;
            }
            return SubjectKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();
        } catch (IOException e) {
            throw new CmsObjectBuilderException(e);
        }
    }
}
