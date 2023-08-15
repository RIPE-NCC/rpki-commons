package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectBuilder;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

/**
 * Creates a RoaCms using the DER encoding specified in the ROA format standard.
 *
 * @see <a href="http://tools.ietf.org/html/draft-ietf-sidr-roa-format-03">ROA format</a>
 */
public class GhostbustersCmsBuilder extends RpkiSignedObjectBuilder {

    private X509ResourceCertificate certificate;
    private String vCardPayload;
    private String signatureProvider;


    public GhostbustersCmsBuilder withCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public GhostbustersCmsBuilder withVCardPayload(String vCardPayload) {
        this.vCardPayload = vCardPayload;
        return this;
    }

    public GhostbustersCmsBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public GhostbustersCms build(PrivateKey privateKey) {
        String location = "unknown.gbr";
        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        parser.parse(ValidationResult.withLocation(location), getEncoded(privateKey));
        return parser.getGhostbustersCms();
    }

    public byte[] getEncoded(PrivateKey privateKey) {
        return generateCms(certificate.getCertificate(), privateKey, signatureProvider, GhostbustersCms.CONTENT_TYPE, vCardPayload.getBytes(StandardCharsets.UTF_8));
    }
}
