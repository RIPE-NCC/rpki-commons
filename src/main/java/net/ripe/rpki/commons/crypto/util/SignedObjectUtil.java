package net.ripe.rpki.commons.crypto.util;

import lombok.Getter;
import lombok.experimental.UtilityClass;
import net.ripe.rpki.commons.crypto.cms.GenericRpkiSignedObjectParser;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.util.RepositoryObjectType;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.joda.time.Instant;

import java.net.URI;

@UtilityClass
public class SignedObjectUtil {
    /**
     * Extract the creation time from an object. This does <emph>not yet</emph> follow the method described in
     * https://datatracker.ietf.org/doc/draft-timbru-sidrops-publication-server-bcp/00/. It differs in that it uses
     * the signing time for RPKI signed objects. This is a trade-off:
     *   * signing-time is more correct when multi-use EE certificates are present.
     *   * signing-time likely does not match the modification time of the CRL.
     *
     * This needs to be revisited in 2024.
     *
     * @param uri URL of the object
     * @param decoded object bytes
     * @return the file creation time of the object
     * @throws NoTimeParsedException if creation time could not be extracted.
     */
    public static Instant getFileCreationTime(URI uri, byte[] decoded) throws NoTimeParsedException {

        final RepositoryObjectType objectType = RepositoryObjectType.parse(uri.toString());
        try {
            switch (objectType) {
                case Manifest:
                case Aspa:
                case Roa:
                case Gbr:
                    var signedObjectParser = new GenericRpkiSignedObjectParser();

                    signedObjectParser.parse(ValidationResult.withLocation(uri), decoded);
                    var signingTime = signedObjectParser.getSigningTime();

                    if (signingTime == null) {
                        return signedObjectParser.getCertificate().getValidityPeriod().getNotValidBefore().toInstant();
                    }
                    return signingTime.toInstant();
                case Certificate:
                    X509ResourceCertificateParser x509CertificateParser = new X509ResourceCertificateParser();
                    x509CertificateParser.parse(ValidationResult.withLocation(uri), decoded);
                    final var cert = x509CertificateParser.getCertificate().getCertificate();
                    return Instant.ofEpochMilli(cert.getNotBefore().getTime());
                case Crl:
                    var x509Crl = X509Crl.parseDerEncoded(decoded, ValidationResult.withLocation(uri));
                    var crl = x509Crl.getCrl();
                    return Instant.ofEpochMilli(crl.getThisUpdate().getTime());
                case Unknown:
                default:
                    throw new NoTimeParsedException(decoded, uri, "Could not determine file type");
            }
        } catch (Exception e) {
            if (e instanceof  NoTimeParsedException) {
                throw e;
            }
            throw new NoTimeParsedException(decoded, uri, "Could not parse object", e);
        }
    }

    @Getter
    public static class NoTimeParsedException extends Exception {
        private static final long serialVersionUID = 1L;

        private byte[] decoded;
        private URI uri;
        public NoTimeParsedException(byte[] decoded, URI uri, String message) {
            super(uri.toString() + ": " + message);
            this.decoded = decoded;
            this.uri = uri;
        }

        public NoTimeParsedException(byte[] decoded, URI uri, String message, Throwable cause) {
            super(uri.toString() + ": " + message, cause);
            this.decoded = decoded;
            this.uri = uri;
        }
    }
}
