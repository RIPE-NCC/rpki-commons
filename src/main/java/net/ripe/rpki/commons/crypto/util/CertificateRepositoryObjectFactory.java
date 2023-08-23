package net.ripe.rpki.commons.crypto.util;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.UnknownCertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.aspa.AspaCms;
import net.ripe.rpki.commons.crypto.cms.aspa.AspaCmsParser;
import net.ripe.rpki.commons.crypto.cms.ghostbuster.GhostbustersCms;
import net.ripe.rpki.commons.crypto.cms.ghostbuster.GhostbustersCmsParser;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParser;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509GenericCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.util.RepositoryObjectType;
import net.ripe.rpki.commons.validation.ValidationChecks;
import net.ripe.rpki.commons.validation.ValidationResult;

public final class CertificateRepositoryObjectFactory {


    private CertificateRepositoryObjectFactory() {
    }

    /**
     * @param encoded the DER encoded object.
     *
     * @return a parsed {@link CertificateRepositoryObject} or {@code null} in case the encoded object has a valid location
     * but its contents can not be parsed.
     */
    public static CertificateRepositoryObject createCertificateRepositoryObject(byte[] encoded, ValidationResult validationResult) {

        RepositoryObjectType objectType = RepositoryObjectType.parse(validationResult.getCurrentLocation().name());

        ValidationChecks.knownObjectType(objectType, validationResult);

        return switch (objectType) {
            case Manifest -> parseManifest(encoded, validationResult);
            case Roa -> parseRoa(encoded, validationResult);
            case Certificate -> parseX509Certificate(encoded, validationResult);
            case Crl -> parseCrl(encoded, validationResult);
            case Gbr -> parseGbr(encoded, validationResult);
            case Aspa -> parseAspa(encoded, validationResult);
            case Unknown -> new UnknownCertificateRepositoryObject(encoded);
        };
    }

    private static X509Crl parseCrl(byte[] encoded, ValidationResult validationResult) {
        return X509Crl.parseDerEncoded(encoded, validationResult);
    }

    private static X509GenericCertificate parseX509Certificate(byte[] encoded, ValidationResult validationResult) {
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        X509GenericCertificate cert = X509ResourceCertificateParser.parseCertificate(temp, encoded);
        validationResult.addAll(temp);
        return cert;
    }

    private static RoaCms parseRoa(byte[] encoded, ValidationResult validationResult) {
        final RoaCmsParser parser = new RoaCmsParser();
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        parser.parse(temp, encoded);
        validationResult.addAll(temp);
        if (parser.isSuccess()) {
            return parser.getRoaCms();
        } else {
            return null;
        }
    }

    private static ManifestCms parseManifest(byte[] encoded, ValidationResult validationResult) {
        final ManifestCmsParser parser = new ManifestCmsParser();
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        parser.parse(temp, encoded);
        validationResult.addAll(temp);
        if (parser.isSuccess()) {
            return parser.getManifestCms();
        } else {
            return null;
        }
    }

    private static GhostbustersCms parseGbr(byte[] encoded, ValidationResult validationResult) {
        final GhostbustersCmsParser parser = new GhostbustersCmsParser();
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        parser.parse(temp, encoded);
        validationResult.addAll(temp);
        if (parser.isSuccess()) {
            return parser.getGhostbustersCms();
        } else {
            return null;
        }
    }

    private static AspaCms parseAspa(byte[] encoded, ValidationResult validationResult) {
        final AspaCmsParser parser = new AspaCmsParser();
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        parser.parse(temp, encoded);
        validationResult.addAll(temp);
        if (parser.isSuccess()) {
            return parser.getAspa();
        } else {
            return null;
        }
    }
}
