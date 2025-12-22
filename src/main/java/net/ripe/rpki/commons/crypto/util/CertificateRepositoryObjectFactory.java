package net.ripe.rpki.commons.crypto.util;

import lombok.extern.slf4j.Slf4j;
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
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.util.RepositoryObjectType;
import net.ripe.rpki.commons.validation.ValidationChecks;
import net.ripe.rpki.commons.validation.ValidationResult;

import static net.ripe.rpki.commons.validation.ValidationString.KNOWN_OBJECT_TYPE;

@Slf4j
public final class CertificateRepositoryObjectFactory {


    private CertificateRepositoryObjectFactory() {
    }

    /**
     * @param encoded the DER encoded object.
     *
     * @return a parsed {@link CertificateRepositoryObject} or {@code null} in case the encoded object has a valid location
     * but its contents can not be parsed.
     */
    @SuppressWarnings("fallthrough")
    public static CertificateRepositoryObject createCertificateRepositoryObject(byte[] encoded, ValidationResult validationResult) {

        RepositoryObjectType objectType = RepositoryObjectType.parse(validationResult.getCurrentLocation().getName());

        ValidationChecks.knownObjectType(objectType, validationResult);

        switch (objectType) {
            case Manifest:
                return parseManifest(encoded, validationResult);
            case Roa:
                return parseRoa(encoded, validationResult);
            case Certificate:
                return parseX509Certificate(encoded, validationResult);
            case Crl:
                return parseCrl(encoded, validationResult);
            case Gbr:
                return parseGbr(encoded, validationResult);
            case Aspa:
                return parseAspa(encoded, validationResult);
            // intentional usage of fall-through: All three cases should result in UnknownCertificateRepositoryObject, yet only two are unsupported.
            case SignedChecklist:
            case TrustAnchorKey:
                log.info("Encountered unsupported object type: {} uri={}", objectType, validationResult.getCurrentLocation().getName());
                validationResult.error(KNOWN_OBJECT_TYPE, validationResult.getCurrentLocation().getName());
            case Unknown:
                return new UnknownCertificateRepositoryObject(encoded);
        }
        throw new IllegalArgumentException("Unrecognized repository object type: " + objectType);
    }

    private static X509Crl parseCrl(byte[] encoded, ValidationResult validationResult) {
        return X509Crl.parseDerEncoded(encoded, validationResult);
    }

    private static X509ResourceCertificate parseX509Certificate(byte[] encoded, ValidationResult validationResult) {
        final ValidationResult temp = ValidationResult.withLocation(validationResult.getCurrentLocation());
        X509ResourceCertificate cert = X509ResourceCertificateParser.parseCertificate(temp, encoded);
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
