package net.ripe.rpki.commons.crypto.util;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;
import java.security.PublicKey;

/**
 * While software keys can be persisted nCipher keys cannot.
 * For KeyPairEntity we put them into a keystore but that did not
 * fit into the architecture for ResourceCertificateRequestData.
 * ResourceCertificateRequestData contains the encoded representation of
 * the subject public key and when it fed into the ResourceCertificateBuilder
 * (which send it further to X509CertificateBuilder) it is wrapped into
 * this class.
 */
public class EncodedPublicKey implements PublicKey {

    private static final long serialVersionUID = 2L;

    private final ASN1Sequence sequence;


    public EncodedPublicKey(byte[] encoded) {
        this.sequence = ASN1Sequence.getInstance(encoded);
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + sequence.size());
        }
        AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        if (!algId.getAlgorithm().on(PKCSObjectIdentifiers.pkcs_1)) {
            throw new IllegalArgumentException("Not a PKCS#1 signature algorithm" + algId.getAlgorithm());
        }
    }

    @Override
    public byte[] getEncoded() {
        try {
            return sequence.getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Lost access to loaded public key data", e);
        }
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }
}
