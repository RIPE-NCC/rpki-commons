package net.ripe.rpki.commons.provisioning.cms;

import net.ripe.rpki.commons.crypto.cms.RPKISignedDataGenerator;
import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.PayloadParser;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;


public class ProvisioningCmsObjectBuilder {

    private static final ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.28");

    private X509Certificate cmsCertificate;

    private X509CRL crl;

    private String signatureProvider = X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;

    private String payloadContent;

    private Instant signingTime = Instant.now();

    public ProvisioningCmsObjectBuilder withCmsCertificate(X509Certificate cmsCertificate) {
        this.cmsCertificate = cmsCertificate;
        return this;
    }

    public ProvisioningCmsObjectBuilder withCrl(X509CRL crl) {
        this.crl = crl;
        return this;
    }

    public ProvisioningCmsObjectBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public ProvisioningCmsObjectBuilder withPayloadContent(AbstractProvisioningPayload payload) {
        this.payloadContent = PayloadParser.serialize(payload);
        return this;
    }

    public ProvisioningCmsObjectBuilder withSigningTime(@NotNull Instant signingTime) {
        this.signingTime = signingTime;
        return this;
    }

    public ProvisioningCmsObject build(PrivateKey privateKey) {
        Validate.notEmpty(payloadContent, "Payload content is required");

        Validate.notNull(cmsCertificate, "cms certificate is required");
        Validate.notNull(crl, "crl is required");

        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser();
        parser.parseCms("n/a", generateCms(privateKey));

        ValidationResult validationResult = parser.getValidationResult();
        if (validationResult.hasFailures()) {
            final String message = validationResult
                .getFailures(new ValidationLocation("generated.cms")).stream()
                .map(ValidationCheck::getKey)
                .collect(Collectors.joining(","));

            throw new IllegalArgumentException("Validation of generated CMS object failed with following errors: " + message +  ".");
        }

        return parser.getProvisioningCmsObject();
    }

    private byte[] generateCms(PrivateKey privateKey) {
        try {
            return doGenerate(privateKey);
        } catch (CMSException | IOException | OperatorCreationException | CRLException | CertificateEncodingException e) {
            throw new ProvisioningCmsObjectBuilderException(e);
        }
    }

    private byte[] doGenerate(PrivateKey privateKey) throws CMSException, IOException, CertificateEncodingException, CRLException, OperatorCreationException {
        RPKISignedDataGenerator generator = new RPKISignedDataGenerator();
        addCertificateAndCrl(generator);
        addSignerInfo(generator, privateKey);

        CMSSignedData data = generator.generate(new CMSProcessableByteArray(CONTENT_TYPE, payloadContent.getBytes(StandardCharsets.UTF_8)), true);

        return data.getEncoded();
    }

    private void addSignerInfo(RPKISignedDataGenerator generator, PrivateKey privateKey) throws OperatorCreationException {
        final ContentSigner signer = new JcaContentSignerBuilder(X509CertificateBuilderHelper.DEFAULT_SIGNATURE_ALGORITHM).setProvider(signatureProvider).build(privateKey);
        final DigestCalculatorProvider digestProvider = BouncyCastleUtil.DIGEST_CALCULATOR_PROVIDER;
        final byte[] ski = X509CertificateUtil.getSubjectKeyIdentifier(cmsCertificate);
        generator.addSignerInfoGenerator(
            new JcaSignerInfoGeneratorBuilder(digestProvider)
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(createSignedAttributes()) {
                    @Override
                    public AttributeTable getAttributes(Map parameters) {
                        return super.getAttributes(parameters).remove(CMSAttributes.cmsAlgorithmProtect);
                    }
                })
            .build(signer, ski));
    }

    private void addCertificateAndCrl(RPKISignedDataGenerator generator) throws CertificateEncodingException, CMSException, CRLException {
        List<X509Extension> certificates = new ArrayList<>();
        certificates.add(cmsCertificate);

        generator.addCertificates(new JcaCertStore(certificates));
        generator.addCRLs(new JcaCRLStore(Collections.singleton(crl)));
    }

    private AttributeTable createSignedAttributes() {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<>();
        // -
        // ReplaceHashtableWithMap
        Attribute signingTimeAttribute = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(new Date(signingTime.toEpochMilli()))));
        attributes.put(CMSAttributes.signingTime, signingTimeAttribute);
        return new AttributeTable(attributes);
    }

}
