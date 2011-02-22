package net.ripe.commons.certification.cms.manifest;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Map;
import java.util.TreeMap;

import net.ripe.commons.certification.cms.CmsObjectBuilder;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.joda.time.DateTime;

public class ManifestCmsBuilder extends CmsObjectBuilder {

    private X509ResourceCertificate certificate;
    private BigInteger number;
    private DateTime thisUpdateTime;
    private DateTime nextUpdateTime;
    private String signatureProvider;
    private Map<String, byte[]> files = new TreeMap<String, byte[]>();


    public ManifestCmsBuilder() {
    }

    public ManifestCmsBuilder putFile(String fileName, byte[] hash) {
        files.put(fileName, hash);
        return this;
    }

    public boolean containsFile(String fileName) {
        return files.containsKey(fileName);
    }

    public ManifestCmsBuilder withCertificate(X509ResourceCertificate signingCertificate) {
        this.certificate = signingCertificate;
        return this;
    }

    public ManifestCmsBuilder withManifestNumber(BigInteger number) {
        this.number = number;
        return this;
    }

    public ManifestCmsBuilder withThisUpdateTime(DateTime instant) {
        this.thisUpdateTime = instant;
        return this;
    }

    public ManifestCmsBuilder withNextUpdateTime(DateTime instant) {
        this.nextUpdateTime = instant;
        return this;
    }

    public ManifestCmsBuilder withSignatureProvider(String signatureProvider) {
    	this.signatureProvider = signatureProvider;
    	return this;
    }

    public ManifestCms build(PrivateKey privateKey) {
    	ManifestCmsParser parser = new ManifestCmsParser();
    	parser.parse("<generated>", generateCms(certificate.getCertificate(), privateKey, signatureProvider, ManifestCms.CONTENT_TYPE, encodeManifest()));
        return parser.getManifestCms();
    }

    public void addFile(String fileName, byte[] contents) {
        byte[] digestValue = ManifestCms.hashContents(contents);
        putFile(fileName, digestValue);
    }

    ASN1Encodable encodeFileAndHash(String fileName, byte[] hash) {
        ASN1Encodable[] seq = { new DERIA5String(fileName, true), new DERBitString(hash) };
        return new DERSequence(seq);
    }

    ASN1Encodable encodeFileList() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        for (Map.Entry<String, byte[]> fileAndHash : files.entrySet()) {
            seq.add(encodeFileAndHash(fileAndHash.getKey(), fileAndHash.getValue()));
        }
        return new DERSequence(seq);
    }

    /**
     * Note: in DER encoding a field with a value equal to its default should
     * NOT be encoded. So the version field should not be present.
     */
    ASN1Encodable encodeManifest() {
        ASN1Encodable[] seq = {
                new DERInteger(number),
                new DERGeneralizedTime(thisUpdateTime.toDate()),
                new DERGeneralizedTime(nextUpdateTime.toDate()),
                new DERObjectIdentifier(ManifestCms.FILE_HASH_ALGORITHM),
                encodeFileList()
        };
        return new DERSequence(seq);
    }
}
