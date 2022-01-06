package net.ripe.rpki.commons.crypto.cms.manifest;

import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectBuilder;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.joda.time.DateTime;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Map;
import java.util.TreeMap;

public class ManifestCmsBuilder extends RpkiSignedObjectBuilder {

    private X509ResourceCertificate certificate;
    private BigInteger number;
    private DateTime thisUpdateTime;
    private DateTime nextUpdateTime;
    private String signatureProvider = X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
    private Map<String, byte[]> files = new TreeMap<>();


    public ManifestCmsBuilder() {
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
        String location = "unknown.mft";
        ManifestCmsParser parser = new ManifestCmsParser();
        parser.parse(ValidationResult.withLocation(location), generateCms(certificate.getCertificate(), privateKey, signatureProvider, new ASN1ObjectIdentifier(ManifestCms.CONTENT_TYPE_OID), encodeManifest()));
        return parser.getManifestCms();
    }

    public void addFile(String fileName, byte[] contents) {
        byte[] digestValue = ManifestCms.hashContents(contents);
        files.put(fileName, digestValue);
    }

    public void addFileHash(String fileName, byte[] hash) {
        assert hash!= null && hash.length == 32: "Hash must be 32 bytes";
        files.put(fileName, hash);
    }

    ASN1Encodable encodeFileAndHash(String fileName, byte[] hash) {
        ASN1Encodable[] seq = {new DERIA5String(fileName, true), new DERBitString(hash)};
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
    byte[] encodeManifest() {
        ASN1Encodable[] seq = {
                new ASN1Integer(number),
                new ASN1GeneralizedTime(thisUpdateTime.toDate()),
                new ASN1GeneralizedTime(nextUpdateTime.toDate()),
                new ASN1ObjectIdentifier(ManifestCms.FILE_HASH_ALGORITHM),
                encodeFileList()
        };
        return Asn1Util.encode(new DERSequence(seq));
    }
}
