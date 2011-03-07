package net.ripe.commons.certification;

import java.security.PublicKey;

/**
 * While software keys can be persisted nCipher keys cannot.
 * For KeyPairEntity we put them into a keystore but that did not
 * fit into the architecture for ResourceCertificateRequestData.
 * ResourceCertificateRequestData contains the encoded representation of
 * the subject public key and when it fed into the ResourceCertificateBuilder
 * (which send it further to X509CertificateBuilder) it is wrapped into
 * this class. As long as only the encoded representation of the key is used
 * this is sufficient.
 *
 */
public class EncodedPublicKey implements PublicKey {

    private static final long serialVersionUID = 1L;

    private final byte[] encoded;


    public EncodedPublicKey(byte[] encoded) { //NOPMD - ArrayIsStoredDirectly
        this.encoded = encoded;
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }

    @Override
    public String getAlgorithm() {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException();
    }
}
