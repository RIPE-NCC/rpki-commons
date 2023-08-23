package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObjectFile;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.jetbrains.annotations.NotNull;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import static net.ripe.rpki.commons.validation.ValidationString.*;


public class X509ResourceCertificateBottomUpValidator implements X509ResourceCertificateValidator {

    private static final int MAX_CHAIN_LENGTH = 30;
    private X509ResourceCertificate certificate;
    private final Collection<X509ResourceCertificate> trustAnchors;
    private final ResourceCertificateLocator locator;
    private final List<CertificateWithLocation> certificates = new LinkedList<>();
    private final ValidationOptions options;
    private final ValidationResult result;
    private ValidationLocation location;


    public X509ResourceCertificateBottomUpValidator(ResourceCertificateLocator locator, X509ResourceCertificate... trustAnchors) {
        this(locator, Arrays.asList(trustAnchors));
    }

    public X509ResourceCertificateBottomUpValidator(ResourceCertificateLocator locator, Collection<X509ResourceCertificate> trustAnchors) {
        this(ValidationOptions.strictValidation(), ValidationResult.withLocation("unknown.cer"), locator, trustAnchors);
    }

    public X509ResourceCertificateBottomUpValidator(ValidationOptions options, ValidationResult result, ResourceCertificateLocator locator, Collection<X509ResourceCertificate> trustAnchors) {
        this.options = options;
        this.result = result;
        this.location = new ValidationLocation("unknown.cer");
        this.locator = locator;
        this.trustAnchors = trustAnchors;
    }

    @Override
    public ValidationResult getValidationResult() {
        return result;
    }

    @Override
    public void validate(String location, X509ResourceCertificate certificate) {
        this.location = new ValidationLocation(location);
        this.certificate = certificate;

        buildCertificationList();
        if (result.hasFailures()) {
            // stop validation: certificate chain too long
            return;
        }

        checkTrustAnchor();

        X509ResourceCertificate parent = certificates.get(0).certificate();
        certificates.remove(0); // No need to validate the root (1st parent) certificate against itself

        IpResourceSet resources = parent.getResources();

        for (CertificateWithLocation certificateWithLocation : certificates) {
            String childLocation = certificateWithLocation.location().name();
            X509ResourceCertificate child = certificateWithLocation.certificate();

            X509Crl crl = getCRL(child, result);
            if (result.hasFailures()) {
                // stop validation: crl cannot be parsed
                return;
            }

            X509ResourceCertificateParentChildValidator validator = ResourceValidatorFactory.getX509ResourceCertificateParentChildStrictValidator(options, result, parent, resources, crl);
            validator.validate(childLocation, child);

            resources = child.deriveResources(resources);
            parent = child;
        }
    }

    private void buildCertificationList() {
        certificates.add(0, new CertificateWithLocation(this.certificate, this.location));
        result.setLocation(this.location);
        if (!result.rejectIfFalse(certificates.size() <= MAX_CHAIN_LENGTH, CERT_CHAIN_LENGTH, Integer.toString(MAX_CHAIN_LENGTH))) {
            return;
        }

        X509ResourceCertificate cert = this.certificate;
        while (!cert.isRoot()) {
            CertificateRepositoryObjectFile<X509ResourceCertificate> parent = locator.findParent(cert);

            if (!result.rejectIfNull(parent, CERT_CHAIN_COMPLETE)) {
                return;
            }

            ValidationLocation parentLocation = new ValidationLocation(parent.name());
            result.setLocation(parentLocation);

            X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
            parser.parse(result, parent.content());
            if (result.hasFailures()) {
                return;
            }

            cert = parser.getCertificate();
            certificates.add(0, new CertificateWithLocation(cert, parentLocation));
            if (!result.rejectIfFalse(certificates.size() <= MAX_CHAIN_LENGTH, CERT_CHAIN_LENGTH, Integer.toString(MAX_CHAIN_LENGTH))) {
                return;
            }
        }

    }

    private X509Crl getCRL(X509ResourceCertificate certificate, ValidationResult validationResult) {
        CertificateRepositoryObjectFile<X509Crl> crlFile = locator.findCrl(certificate);
        if (crlFile == null) {
            return null;
        }
        return X509Crl.parseDerEncoded(crlFile.content(), validationResult);
    }

    private void checkTrustAnchor() {
        if ((trustAnchors != null) && (!trustAnchors.isEmpty())) {
            result.rejectIfFalse(trustAnchors.contains(certificates.get(0).certificate()), ROOT_IS_TA);
        }
    }

    private record CertificateWithLocation(@NotNull X509ResourceCertificate certificate, @NotNull ValidationLocation location) {
    }
}
