package net.ripe.commons.provisioning.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
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

    private X509CRL crl;

    private String signatureProvider;


    public CmsObjectBuilder withCertificate(X509Certificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public CmsObjectBuilder withCrl(X509CRL crl) {
        this.crl = crl;
        return this;
    }

    public CmsObjectBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public CmsObject build(PrivateKey privateKey) {
        Validate.notNull(certificate, "certificate is required");
        Validate.notNull(crl, "crl is required");
        Validate.notNull(signatureProvider, "signatureProvider is required");

        return new CmsObject(generateCms(privateKey, encodableMessageContent()), certificate);
    }

    private byte[] generateCms(PrivateKey privateKey, ASN1Encodable encodableContent) {
        try {
            return doGenerate(privateKey, encodableContent);
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
        } catch (CertificateEncodingException e) {
            throw new CmsObjectBuilderException(e);
        }
    }

    private byte[] doGenerate(PrivateKey privateKey, ASN1Encodable encodableContent) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertStoreException, CMSException, NoSuchProviderException, IOException, CertificateEncodingException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        addCertificateAndCrl(generator);
        generator.addSigner(privateKey, getSubjectKeyIdentifier(certificate), CmsObject.DIGEST_ALGORITHM_OID, createSignedAttributes(), null);

        byte[] content = encode(encodableContent);
        CMSSignedData data = generator.generate(CmsObject.CONTENT_TYPE, new CMSProcessableByteArray(content), true, signatureProvider);

        return data.getEncoded();
    }

    private void addCertificateAndCrl(CMSSignedDataGenerator generator) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertStoreException, CMSException {
        //        CollectionCertStoreParameters certStoreParameters = new CollectionCertStoreParameters(Arrays.asList(certificate, crl));
        CollectionCertStoreParameters certStoreParameters = new CollectionCertStoreParameters(Collections.singleton(certificate));
        CertStore certStore = CertStore.getInstance("Collection", certStoreParameters);
        generator.addCertificatesAndCRLs(certStore);
    }

    private AttributeTable createSignedAttributes() {
        Hashtable<DERObjectIdentifier, Attribute> attributes = new Hashtable<DERObjectIdentifier, Attribute>(); //NOPMD - ReplaceHashtableWithMap
        Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date(DateTimeUtils.currentTimeMillis()))));
        attributes.put(CMSAttributes.signingTime, signingTimeAttribute);
        return new AttributeTable(attributes);
    }

    private ASN1Encodable encodableMessageContent() {
        return new DEROctetString(new byte[] {'h', 'e', 'l', 'l', 'o'}); // TODO:
    }

    private byte[] encode(ASN1Encodable value) {
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

    private byte[] getSubjectKeyIdentifier(X509Extension certificate) {
        try {
            byte[] extensionValue = certificate.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
            Validate.notNull(extensionValue, "certificate must contain SubjectKeyIdentifier extension");
            return SubjectKeyIdentifier.getInstance(X509ExtensionUtil.fromExtensionValue(extensionValue)).getKeyIdentifier();
        } catch (IOException e) {
            throw new CmsObjectBuilderException(e);
        }
    }
}
