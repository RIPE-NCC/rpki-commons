package net.ripe.rpki.commons.crypto.util;

import lombok.Getter;
import lombok.experimental.UtilityClass;
import net.ripe.rpki.commons.crypto.cms.GenericRpkiSignedObjectParser;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateParser;
import net.ripe.rpki.commons.util.RepositoryObjectType;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.joda.time.Instant;

import java.net.URI;

@UtilityClass
public class SignedObjectUtil {
    /**
     * Extract the creation time from an object. This uses the signing time for RPKI signed objects with fallback
     * to notBefore if that is not present.
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
                    var genericCert = X509CertificateParser.parseCertificate(ValidationResult.withLocation(uri), decoded);
                    return Instant.ofEpochMilli(genericCert.getCertificate().getNotBefore().getTime());
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
