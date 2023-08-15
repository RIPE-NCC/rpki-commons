package net.ripe.rpki.commons.validation;


import java.time.Duration;

/**
 * User controlled options to use when validating objects.
 */
public class ValidationOptions {

    /**
     * Flag to switch whether we would reject stale manifest and CRL under certain max stale period.
     * Turning this on will activate the {@link ValidationOptions#crlMaxStalePeriod} and {@link ValidationOptions#manifestMaxStalePeriod} checks.
     *
     */
    private boolean strictManifestCRLValidityChecks;

    /**
     * When {@link ValidationOptions#strictManifestCRLValidityChecks} is enabled, this is the grace period for the
     * NEXT_UPDATE_TIME of CRL. When a crl is in the grace period, the crl causes a warning on
     * validation instead of a failure.
     */
    private final Duration crlMaxStalePeriod;

    /**
     *  When {@link ValidationOptions#strictManifestCRLValidityChecks} is enabled, this is the grace period for the
     *  NEXT_UPDATE_TIME of Manifest. When a manifest is in the grace period, the manifest causes
     *  a warning on validation instead of a failure.
     *
     * This grace period is not applied to the EE certificate.
     */
    private final Duration manifestMaxStalePeriod;

    /**
     * Setting this will allow resources over claim on X509ResourceCertificateParentChildLooseValidator.
     * Instead of rejected, it will only produce warning on overclaim of child resources.
     */
    private boolean allowOverclaimParentChild = false;

    private ValidationOptions(Boolean strictManifestCRLValidityChecks, Duration crlMaxStalePeriod,
                              Duration manifestMaxStalePeriod) {
        this.strictManifestCRLValidityChecks = strictManifestCRLValidityChecks;
        this.crlMaxStalePeriod = crlMaxStalePeriod;
        this.manifestMaxStalePeriod = manifestMaxStalePeriod;
    }

    /**
     * Validate manifest in a strict way, i.e. the whole manifest is considered invalid if any of the references
     * on it are not found in the downloaded data or cache. Set grace periods to 0.
     */
    public static ValidationOptions strictValidation() {
        return new ValidationOptions(true, Duration.ZERO, Duration.ZERO);
    }

    /**
     * Validate manifest in a non-strict way, i.e. the if any of the references on it are not found, a warning is
     * emitted and the validation process continues for the correct references. Set grace periods to 0.
     */
    public static ValidationOptions backCompatibleRipeNccValidator() {
        return new ValidationOptions(false, Duration.ZERO, Duration.ZERO);
    }

    /**
     * This mode is introduced for internal testing purposes.
     * <p>
     * RIPE regularly refresh Crl/Manifest in our RPKI core every 16 hours,with validity for 24 hours.
     * Leaving 8 for troubleshooting if needed. This one will invalidates a crl/manifest with still 7 hours
     * remaining, indicating something wrong with refresh.
     *
     * @return
     */
    public static ValidationOptions paranoidTestValidations() {
        return new ValidationOptions(true, Duration.ofHours(-7), Duration.ofHours(-7));
    }

    public static ValidationOptions withStaleConfigurations(Duration maxCrlStalePeriod, Duration maxMftStalePeriod) {
        return new ValidationOptions(true, maxCrlStalePeriod, maxMftStalePeriod);
    }

    public Duration getCrlMaxStalePeriod() {
        return this.crlMaxStalePeriod;
    }

    public Duration getManifestMaxStalePeriod() {
        return manifestMaxStalePeriod;
    }

    public boolean isAllowOverclaimParentChild() {
        return allowOverclaimParentChild;
    }

    public void setAllowOverclaimParentChild(boolean allowOverclaimParentChild) {
        this.allowOverclaimParentChild = allowOverclaimParentChild;
    }

    public boolean isStrictManifestCRLValidityChecks() {
        return strictManifestCRLValidityChecks;
    }

    public void setStrictManifestCRLValidityChecks(boolean strictManifestCRLValidityChecks) {
        this.strictManifestCRLValidityChecks = strictManifestCRLValidityChecks;
    }
}
