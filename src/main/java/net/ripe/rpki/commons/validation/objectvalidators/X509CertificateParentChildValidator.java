package net.ripe.rpki.commons.validation.objectvalidators;

import com.google.common.primitives.Booleans;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.AbstractX509CertificateWrapper;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.x509.Extension;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Arrays;

import static net.ripe.rpki.commons.crypto.JavaSecurityConstants.CRLSIGN_INDEX;
import static net.ripe.rpki.commons.crypto.JavaSecurityConstants.DIG_SIGN_INDEX;
import static net.ripe.rpki.commons.crypto.JavaSecurityConstants.KEYCERTSIGN_INDEX;
import static net.ripe.rpki.commons.validation.ValidationString.*;


public abstract class X509CertificateParentChildValidator<T extends AbstractX509CertificateWrapper> {

    private final T parent;

    protected T child;

    private final X509Crl crl;

    protected final ValidationOptions options;
    protected final ValidationResult result;


    public X509CertificateParentChildValidator(ValidationOptions options, ValidationResult result, T parent, X509Crl crl) {
        this.options = options;
        this.result = result;
        this.parent = parent;
        this.crl = crl;
    }

    public void validate(String location, T certificate) {
        this.child = certificate;
        result.setLocation(new ValidationLocation(location));

        verifySignature();
        verifyValidity();
        verifyCrl();
        verifyIssuer();
        verifyKeyUsage();
        verifyAuthorityKeyIdentifier();
    }

    public ValidationResult getValidationResult() {
        return result;
    }

    protected T getChild() {
        return child;
    }

    private void verifySignature() {
        result.rejectIfFalse(parent.isCa(), ISSUER_IS_CA);

        boolean errorOccurred = false;
        try {
            child.verify(parent.getPublicKey()); // signed with issuer's public key
        } catch (SignatureException | InvalidKeyException e) {
            errorOccurred = true;
        }

        result.rejectIfTrue(errorOccurred, SIGNATURE_VALID);
    }

    private void verifyCrl() {
        if (crl == null) {
            result.rejectIfFalse(child.isRoot(), CRL_REQUIRED);
            return;
        }

        boolean errorOccurred = false;
        try {
            crl.verify(parent.getPublicKey());
        } catch (SignatureException e) {
            errorOccurred = true;
        }

        result.rejectIfTrue(errorOccurred, CRL_SIGNATURE_VALID);
        result.rejectIfTrue(crl.isRevoked(child.getCertificate()), CERT_NOT_REVOKED);
    }

    protected void verifyValidity() {
        final var now = result.now();
        final var notValidBefore = child.getValidityPeriod().notValidBefore();
        final var notValidAfter = child.getValidityPeriod().notValidAfter();
        result.rejectIfTrue(now.isBefore(notValidBefore), NOT_VALID_BEFORE, notValidBefore.toString());
        result.rejectIfTrue(now.isAfter(notValidAfter), NOT_VALID_AFTER, notValidAfter.toString());
    }

    private void verifyIssuer() {
        result.rejectIfFalse(parent.getSubject().equals(child.getIssuer()), PREV_SUBJECT_EQ_ISSUER);
    }

    /**
     * https://datatracker.ietf.org/doc/html/rfc6487#section-4.8.4
     *
     * KeyUsage validation added as warning to be similar to current checks.
     */
    protected void verifyKeyUsage() {
        boolean[] keyUsage = child.getCertificate().getKeyUsage();
        if (!result.warnIfNull(keyUsage, KEY_USAGE_EXT_PRESENT)) {
            return;
        }

        if (!result.rejectIfFalse(child.getCertificate().getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()), KEY_USAGE_EXT_CRITICAL)) {
            return;
        }

        if (child.isCa()) {
            if (result.warnIfFalse(Booleans.countTrue(keyUsage) == 2, KEY_USAGE_INVALID)) {
                result.warnIfFalse(keyUsage[KEYCERTSIGN_INDEX], KEY_CERT_SIGN);
                result.warnIfFalse(keyUsage[CRLSIGN_INDEX], CRL_SIGN);
            }
        } else {
            if (result.warnIfFalse(Booleans.countTrue(keyUsage) == 1, KEY_USAGE_INVALID)) {
                result.warnIfFalse(keyUsage[DIG_SIGN_INDEX], DIG_SIGN);
            }
        }
    }

    private void verifyAuthorityKeyIdentifier() {
        if (child.isRoot()) {
            // self-signed cert does not have AKI
            return;
        }
        byte[] ski = parent.getSubjectKeyIdentifier();
        byte[] aki = child.getAuthorityKeyIdentifier();
        if ((!result.rejectIfNull(ski, SKI_PRESENT)) || (!result.rejectIfNull(aki, AKI_PRESENT))) {
            return;
        }
        result.rejectIfFalse(Arrays.equals(ski, aki), PREV_SKI_EQ_AKI);
    }

}
